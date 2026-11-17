#define _GNU_SOURCE
/*
 * elgato-hd60s -- userspace capture driver for Elgato Game Capture HD60 S
 * USB ID: 0fd9:0074
 *
 * Reverse-engineered from USB traffic captures.
 * Video: raw YUY2 (YUYV 4:2:2) 1920x1080, written to stdout (or straight
 * into an auto-launched ffplay when stdout is a terminal).
 *
 * Usage:
 *   ./capture                       # opens ffplay + pw-cat (audio) automatically
 *   ./capture -m                    # same, but muted
 *   ./capture | ffplay -f rawvideo -pixel_format yuyv422 -framerate 60 \
 *                      -video_size 1920x1080 -i -
 *   ./capture -a audio.raw > video.yuv   # also dump audio (s16le, 48 kHz, stereo)
 *
 * ── Stream format (verified on Linux, alt setting 2, 1080p60 source) ──────
 *
 *   Every line is 3840 bytes of YUY2 followed by a trailer:
 *     short:  ff 00 00 XY                                (4 bytes)
 *     long:   ff 00 ff 02 <8-byte payload> ff 00 00 XY   (16 bytes)
 *
 *   XY describes the line that FOLLOWS the trailer:
 *     0x80 = active video line, 0xab = vertical blanking line.
 *
 *   A frame is 1080 active lines + 45 blanking lines (1125 total, standard
 *   1080p timing).  No data is lost on the USB side when enough isochronous
 *   transfers are queued.
 *
 *   The 8-byte long-trailer payload is embedded audio: two stereo frames of
 *   s16le PCM at 48 kHz (~24000 payloads/s = 192 KB/s).  Verified with a
 *   440 Hz test tone, including left/right channel separation.
 */

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>

#include "init_sequence.h"

#define VID                 0x0fd9
#define PID                 0x0074

#define IFACE_VIDEO         0
#define ALT_ISO             2       /* 32768 bytes per 125us microframe */
#define EP_VIDEO            0x83    /* EP3 IN isochronous */

#define WIDTH               1920
#define HEIGHT              1080
#define LINE_BYTES          (WIDTH * 2)          /* 3840 */
#define FRAME_BYTES         ((size_t)LINE_BYTES * HEIGHT)

#define ISO_PACKET_SIZE      32768
#define ISO_PACKETS_PER_URB  64                  /* 8 ms per transfer */
#define NUM_TRANSFERS        16                  /* 128 ms queued */
#define ISO_BUF_SIZE         (ISO_PACKETS_PER_URB * ISO_PACKET_SIZE)

#define LOOPBACK_LABEL      "Elgato HD60 S"      /* v4l2loopback card_label */

static volatile sig_atomic_t g_running = 1;
static int g_video_fd = STDOUT_FILENO;   /* where frames are written */
static void sig_handler(int sig) { (void)sig; g_running = 0; }

/* ── Statistics ──────────────────────────────────────────────────────────── */

static uint64_t st_usb_bytes, st_iso_err_pkts, st_empty_pkts;
static uint64_t st_frames_ok, st_frames_bad, st_frames_dropped_ring;
static uint64_t st_resyncs, st_audio_bytes;

/* ── Output ring (USB callback never blocks on write) ────────────────────── */

#define RING_BUFS 6
static uint8_t        *ring_frames[RING_BUFS];
static int             ring_head, ring_tail, ring_done;
static pthread_mutex_t ring_mutex     = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  ring_not_empty = PTHREAD_COND_INITIALIZER;

static void *write_thread_fn(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&ring_mutex);
        while (ring_head == ring_tail && !ring_done)
            pthread_cond_wait(&ring_not_empty, &ring_mutex);
        if (ring_head == ring_tail) {
            pthread_mutex_unlock(&ring_mutex);
            break;
        }
        int slot = ring_tail % RING_BUFS;
        pthread_mutex_unlock(&ring_mutex);

        size_t off = 0;
        while (off < FRAME_BYTES) {
            ssize_t w = write(g_video_fd, ring_frames[slot] + off, FRAME_BYTES - off);
            if (w <= 0) { g_running = 0; break; }   /* reader went away */
            off += (size_t)w;
        }

        pthread_mutex_lock(&ring_mutex);
        ring_tail++;
        pthread_mutex_unlock(&ring_mutex);
        if (!g_running) break;
    }
    return NULL;
}

/* Returns the frame buffer the parser should fill next, or NULL if the ring
 * is full (frame will be parsed but discarded). */
static uint8_t *ring_acquire(void)
{
    uint8_t *p = NULL;
    pthread_mutex_lock(&ring_mutex);
    if (ring_head - ring_tail < RING_BUFS)
        p = ring_frames[ring_head % RING_BUFS];
    pthread_mutex_unlock(&ring_mutex);
    return p;
}

static void ring_commit(void)
{
    pthread_mutex_lock(&ring_mutex);
    ring_head++;
    pthread_mutex_unlock(&ring_mutex);
    pthread_cond_signal(&ring_not_empty);
}

/* ── Stream parser ───────────────────────────────────────────────────────── */

enum pstate { P_HUNT, P_LINE, P_TRAILER };

static enum pstate ps = P_HUNT;
static int      ps_line_active;          /* type of the line being received */
static int      ps_line_pos;             /* bytes of current line received  */
static uint8_t  ps_trl[16];              /* trailer accumulator             */
static int      ps_trl_len;
static uint32_t ps_hunt_win;             /* last 4 bytes seen while hunting */

static uint8_t *fr_buf;                  /* destination frame (may be NULL) */
static int      fr_rows;                 /* active rows received this frame */
static int      fr_valid;                /* frame started cleanly, no errors */
static uint8_t  scratch_line[LINE_BYTES];/* sink for blanking/discarded lines */

/* ── Audio ───────────────────────────────────────────────────────────────── */

static FILE    *audio_out;               /* -a FILE dump                    */
static int      audio_fd = -1;           /* non-blocking pipe to pw-cat     */
static uint8_t  audio_chunk[1024];       /* ~5 ms of audio per write        */
static size_t   audio_chunk_len;
static uint64_t st_audio_drops;

static void audio_payload(const uint8_t *pcm8)
{
    st_audio_bytes += 8;
    if (audio_out)
        fwrite(pcm8, 1, 8, audio_out);
    if (audio_fd >= 0) {
        memcpy(audio_chunk + audio_chunk_len, pcm8, 8);
        audio_chunk_len += 8;
        if (audio_chunk_len == sizeof(audio_chunk)) {
            /* <= PIPE_BUF, so the write is all-or-nothing.  If the player
             * falls behind, drop audio rather than stall the USB thread. */
            if (write(audio_fd, audio_chunk, audio_chunk_len) < 0) {
                if (errno == EPIPE) {
                    fprintf(stderr, "[audio] player exited, continuing without audio\n");
                    close(audio_fd);
                    audio_fd = -1;
                } else {
                    st_audio_drops++;
                }
            }
            audio_chunk_len = 0;
        }
    }
}

static void frame_start(void)
{
    fr_buf   = ring_acquire();
    if (!fr_buf) st_frames_dropped_ring++;
    fr_rows  = 0;
    fr_valid = 1;
}

static void frame_end(void)
{
    if (fr_valid && fr_rows == HEIGHT) {
        st_frames_ok++;
        if (fr_buf) ring_commit();
    } else if (fr_rows > 0) {
        st_frames_bad++;
    }
    fr_buf   = NULL;
    fr_rows  = 0;
    fr_valid = 0;
}

/* Called when a trailer finished; `next_active` is the XY flag. */
static void begin_line(int next_active)
{
    if (ps_line_active && !next_active)
        frame_end();                     /* active -> blanking */
    else if (!ps_line_active && next_active)
        frame_start();                   /* blanking -> active */
    ps_line_active = next_active;
    ps_line_pos    = 0;
    ps             = P_LINE;
}

static void lost_sync(void)
{
    st_resyncs++;
    fr_valid    = 0;                     /* current frame is corrupt */
    ps          = P_HUNT;
    ps_hunt_win = 0;
}

static void parse(const uint8_t *p, size_t n)
{
    while (n) {
        switch (ps) {
        case P_HUNT: {
            /* Look for ff 00 00 {80|ab}.  After it, a line begins. */
            while (n) {
                ps_hunt_win = (ps_hunt_win << 8) | *p++;
                n--;
                if (ps_hunt_win == 0xff000080u || ps_hunt_win == 0xff0000abu) {
                    int act = (ps_hunt_win & 0xff) == 0x80;
                    /* We don't know where in the frame we are: make sure the
                     * partial frame is discarded, and if we landed in active
                     * video, wait for the next blanking->active edge. */
                    fr_valid = 0;
                    ps_line_active = act;
                    ps_line_pos = 0;
                    ps = P_LINE;
                    break;
                }
            }
            break;
        }

        case P_LINE: {
            size_t want = (size_t)(LINE_BYTES - ps_line_pos);
            size_t take = n < want ? n : want;
            uint8_t *dst;
            if (ps_line_active && fr_buf && fr_valid && fr_rows < HEIGHT)
                dst = fr_buf + (size_t)fr_rows * LINE_BYTES;
            else
                dst = scratch_line;
            memcpy(dst + ps_line_pos, p, take);
            ps_line_pos += (int)take;
            p += take; n -= take;
            if (ps_line_pos == LINE_BYTES) {
                if (ps_line_active) fr_rows++;
                ps = P_TRAILER;
                ps_trl_len = 0;
            }
            break;
        }

        case P_TRAILER: {
            ps_trl[ps_trl_len++] = *p++;
            n--;
            if (ps_trl_len == 4) {
                if (ps_trl[0] != 0xff || ps_trl[1] != 0x00) { lost_sync(); break; }
                if (ps_trl[2] == 0x00) {                       /* short */
                    if (ps_trl[3] == 0x80)      begin_line(1);
                    else if (ps_trl[3] == 0xab) begin_line(0);
                    else lost_sync();
                } else if (ps_trl[2] != 0xff || ps_trl[3] != 0x02) {
                    lost_sync();
                }
                /* else: long trailer, keep accumulating */
            } else if (ps_trl_len == 16) {
                if (ps_trl[12] != 0xff || ps_trl[13] != 0x00 || ps_trl[14] != 0x00 ||
                    (ps_trl[15] != 0x80 && ps_trl[15] != 0xab)) {
                    lost_sync();
                    break;
                }
                audio_payload(ps_trl + 4);
                begin_line(ps_trl[15] == 0x80);
            }
            break;
        }
        }
    }
}

/* ── USB ─────────────────────────────────────────────────────────────────── */

static int g_inflight;

static void LIBUSB_CALL iso_callback(struct libusb_transfer *t)
{
    if (t->status == LIBUSB_TRANSFER_COMPLETED) {
        for (int i = 0; i < t->num_iso_packets; i++) {
            struct libusb_iso_packet_descriptor *pkt = &t->iso_packet_desc[i];
            if (pkt->status != LIBUSB_TRANSFER_COMPLETED) {
                st_iso_err_pkts++;
                /* A missing packet means missing bytes: the parser would
                 * otherwise silently shift the picture.  Force a resync. */
                if (ps != P_HUNT) lost_sync();
                continue;
            }
            if (pkt->actual_length == 0) { st_empty_pkts++; continue; }
            st_usb_bytes += pkt->actual_length;
            parse(libusb_get_iso_packet_buffer_simple(t, i), pkt->actual_length);
        }
    } else if (t->status == LIBUSB_TRANSFER_NO_DEVICE) {
        fprintf(stderr, "[usb] device disconnected\n");
        g_running = 0;
    } else if (t->status != LIBUSB_TRANSFER_CANCELLED) {
        fprintf(stderr, "[usb] transfer status: %s\n", libusb_error_name(t->status));
    }

    if (g_running && t->status != LIBUSB_TRANSFER_NO_DEVICE &&
        t->status != LIBUSB_TRANSFER_CANCELLED &&
        libusb_submit_transfer(t) == 0)
        return;

    g_inflight--;
}

static void send_init_sequence(libusb_device_handle *dev)
{
    uint8_t rxbuf[16];
    int errors = 0;

    fprintf(stderr, "[init] sending %d commands...\n", INIT_SEQ_LEN);
    for (int i = 0; i < INIT_SEQ_LEN; i++) {
        const struct init_cmd *c = &init_sequence[i];
        int r = libusb_control_transfer(dev,
                    LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
                    c->brequest, c->wvalue, 0, (unsigned char *)c->data, c->len, 2000);
        if (r < 0 && errors++ < 10)
            fprintf(stderr, "  [%d] req 0x%02x val 0x%04x len %d: %s\n",
                    i, c->brequest, c->wvalue, c->len, libusb_error_name(r));

        /* Windows reads back an ack after each command write. */
        if (c->brequest == 0xc0 && c->wvalue == 0x5066 && c->len > 0)
            libusb_control_transfer(dev,
                LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
                0xc0, 0x5066, 0, rxbuf, (c->len == 5) ? 3 : 1, 500);
    }
    fprintf(stderr, "[init] done (%d errors)\n", errors);
}

/* Start `argv` with its stdin connected to a new pipe; returns the pid and
 * stores the pipe's write end in *wfd. */
static pid_t spawn_reader(char *const argv[], int *wfd)
{
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) < 0) { perror("pipe"); return -1; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        dup2(pfd[0], STDIN_FILENO);      /* dup2 clears O_CLOEXEC on fd 0 */
        execvp(argv[0], argv);
        fprintf(stderr, "exec %s: %s\n", argv[0], strerror(errno));
        _exit(1);
    }
    close(pfd[0]);
    *wfd = pfd[1];
    return pid;
}

/* ── v4l2loopback output ─────────────────────────────────────────────────── */

/* Find the v4l2loopback device whose name is LOOPBACK_LABEL. */
static int find_loopback(char *path, size_t pathlen)
{
    DIR *d = opendir("/sys/class/video4linux");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)) && found < 0) {
        if (strncmp(e->d_name, "video", 5) != 0) continue;
        char namefile[300], name[128] = "";
        snprintf(namefile, sizeof(namefile), "/sys/class/video4linux/%s/name", e->d_name);
        FILE *f = fopen(namefile, "r");
        if (!f) continue;
        if (fgets(name, sizeof(name), f)) name[strcspn(name, "\n")] = 0;
        fclose(f);
        if (strcmp(name, LOOPBACK_LABEL) == 0) {
            snprintf(path, pathlen, "/dev/%s", e->d_name);
            found = 0;
        }
    }
    closedir(d);
    return found;
}

static int open_v4l2_output(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }

    struct v4l2_format fmt = {0};
    fmt.type                 = V4L2_BUF_TYPE_VIDEO_OUTPUT;
    fmt.fmt.pix.width        = WIDTH;
    fmt.fmt.pix.height       = HEIGHT;
    fmt.fmt.pix.pixelformat  = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field        = V4L2_FIELD_NONE;
    fmt.fmt.pix.bytesperline = LINE_BYTES;
    fmt.fmt.pix.sizeimage    = FRAME_BYTES;
    fmt.fmt.pix.colorspace   = V4L2_COLORSPACE_REC709;
    if (ioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        fprintf(stderr, "%s: VIDIOC_S_FMT: %s (is it a v4l2loopback device?)\n",
                path, strerror(errno));
        close(fd);
        return -1;
    }

    struct v4l2_streamparm parm = {0};
    parm.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
    parm.parm.output.timeperframe.numerator   = 1;
    parm.parm.output.timeperframe.denominator = 60;
    ioctl(fd, VIDIOC_S_PARM, &parm);     /* best effort */
    return fd;
}

/* While there's no HDMI signal, keep feeding black frames so the virtual
 * camera stays visible to apps (exclusive_caps hides idle devices). */
static uint8_t *black_frame;

static void push_black_frame(void)
{
    if (fr_buf) {                        /* abandon a half-received frame */
        fr_buf   = NULL;
        fr_valid = 0;
    }
    uint8_t *slot = ring_acquire();
    if (!slot) return;
    memcpy(slot, black_frame, FRAME_BYTES);
    ring_commit();
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-V | -o /dev/videoN] [-a audio_out.raw] [-m] [-n]\n"
        "\n"
        "  (no option)  stdout is a terminal: preview in ffplay with sound\n"
        "               otherwise: raw YUYV 1920x1080 frames on stdout\n"
        "  -V           virtual camera + microphone: write video to the\n"
        "               v4l2loopback device labelled \"" LOOPBACK_LABEL "\" and\n"
        "               publish audio as a PipeWire source\n"
        "  -o DEV       like -V, but with an explicit v4l2loopback device\n"
        "  -a FILE      also write audio to FILE (s16le, 48 kHz, stereo)\n"
        "  -m           no audio (preview / virtual microphone)\n"
        "  -n           skip the init sequence\n", argv0);
}

int main(int argc, char **argv)
{
    const char *audio_path = NULL;
    const char *v4l2_path = NULL;
    char v4l2_found[320];
    int skip_init = 0, mute = 0, virt = 0, opt;
    while ((opt = getopt(argc, argv, "Vo:a:mnh")) != -1) {
        switch (opt) {
        case 'V': virt = 1; break;
        case 'o': virt = 1; v4l2_path = optarg; break;
        case 'a': audio_path = optarg; break;
        case 'm': mute = 1; break;
        case 'n': skip_init = 1; break;
        default:  usage(argv[0]); return 2;
        }
    }

    libusb_context *ctx = NULL;
    libusb_device_handle *dev = NULL;
    struct libusb_transfer *xfers[NUM_TRANSFERS] = {0};
    pid_t ffplay_pid = -1, audio_pid = -1;
    pthread_t wt;
    int wt_started = 0, claimed = 0, ret = 1;

    struct sigaction sa = { .sa_handler = sig_handler };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    for (int i = 0; i < RING_BUFS; i++)
        if (!(ring_frames[i] = malloc(FRAME_BYTES))) { perror("malloc"); return 1; }

    if (virt) {
        if (!v4l2_path) {
            if (find_loopback(v4l2_found, sizeof(v4l2_found)) < 0) {
                fprintf(stderr,
                    "No v4l2loopback device named \"" LOOPBACK_LABEL "\" found.  Load it with:\n"
                    "  sudo modprobe v4l2loopback video_nr=60 card_label=\"" LOOPBACK_LABEL "\" exclusive_caps=1\n");
                return 1;
            }
            v4l2_path = v4l2_found;
        }
        if ((g_video_fd = open_v4l2_output(v4l2_path)) < 0) return 1;
        if (!(black_frame = malloc(FRAME_BYTES))) { perror("malloc"); return 1; }
        for (size_t i = 0; i < FRAME_BYTES; i += 4) {
            black_frame[i] = 0x10; black_frame[i + 1] = 0x80;
            black_frame[i + 2] = 0x10; black_frame[i + 3] = 0x80;
        }
        fprintf(stderr, "[v4l2] virtual camera: %s\n", v4l2_path);
    }

    if (audio_path && !(audio_out = fopen(audio_path, "wb"))) {
        perror(audio_path);
        return 1;
    }

    int r = libusb_init(&ctx);
    if (r < 0) { fprintf(stderr, "libusb_init: %s\n", libusb_error_name(r)); return 1; }

    dev = libusb_open_device_with_vid_pid(ctx, VID, PID);
    if (!dev) {
        fprintf(stderr, "Device %04x:%04x not found (plugged in? permissions?)\n", VID, PID);
        goto out;
    }
    fprintf(stderr, "[open] Elgato HD60 S found\n");
    libusb_set_auto_detach_kernel_driver(dev, 1);

    r = libusb_claim_interface(dev, IFACE_VIDEO);
    if (r == LIBUSB_ERROR_BUSY) {
        fprintf(stderr, "The card is in use by another program (is the hd60s-capture "
                        "service running?  systemctl --user stop hd60s-capture)\n");
        goto out;
    }
    if (r < 0) { fprintf(stderr, "claim interface: %s\n", libusb_error_name(r)); goto out; }
    claimed = 1;

    /* Make sure we start from alt 0 (no bandwidth) so the init sees an idle device. */
    libusb_set_interface_alt_setting(dev, IFACE_VIDEO, 0);

    if (!skip_init)
        send_init_sequence(dev);

    r = libusb_set_interface_alt_setting(dev, IFACE_VIDEO, ALT_ISO);
    if (r < 0) { fprintf(stderr, "set alt %d: %s\n", ALT_ISO, libusb_error_name(r)); goto out; }

    if (virt) {
        if (!mute) {
            char *pwcat_argv[] = { "pw-cat", "--playback", "--raw",
                "--format", "s16", "--rate", "48000", "--channels", "2",
                "--latency", "20ms",
                "-P", "{ media.class = \"Audio/Source\" node.name = \"elgato_hd60s\" "
                      "node.description = \"" LOOPBACK_LABEL "\" }",
                "-", NULL };
            audio_pid = spawn_reader(pwcat_argv, &audio_fd);
            if (audio_pid < 0) {
                fprintf(stderr, "[audio] could not start pw-cat, continuing without audio\n");
                audio_fd = -1;
            } else {
                fcntl(audio_fd, F_SETFL, O_NONBLOCK);
                fprintf(stderr, "[audio] virtual microphone \"" LOOPBACK_LABEL "\" (pw-cat pid %d)\n",
                        (int)audio_pid);
            }
        }
    } else if (isatty(STDOUT_FILENO)) {
        /* Preview mode.  Keep the video pipe at ~1 frame so a hiccup in
         * ffplay can't build up a permanent lag behind the audio. */
        char *ffplay_argv[] = { "ffplay", "-loglevel", "warning",
            "-window_title", "Elgato HD60 S",
            "-f", "rawvideo", "-pixel_format", "yuyv422",
            "-video_size", "1920x1080", "-framerate", "60",
            "-fflags", "nobuffer", "-i", "-", NULL };
        int vfd;
        ffplay_pid = spawn_reader(ffplay_argv, &vfd);
        if (ffplay_pid < 0) goto out;
        dup2(vfd, STDOUT_FILENO);
        close(vfd);
        fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 4 * 1024 * 1024);
        fprintf(stderr, "[ffplay] launched (pid %d), Ctrl+C to stop\n", (int)ffplay_pid);

        if (!mute) {
            char *pwcat_argv[] = { "pw-cat", "--playback", "--raw",
                "--format", "s16", "--rate", "48000", "--channels", "2",
                "--latency", "20ms",
                "-P", "{ media.name = \"Elgato HD60 S\" node.description = \"Elgato HD60 S\" }",
                "-", NULL };
            audio_pid = spawn_reader(pwcat_argv, &audio_fd);
            if (audio_pid < 0) {
                fprintf(stderr, "[audio] could not start pw-cat, continuing without audio\n");
                audio_fd = -1;
            } else {
                fcntl(audio_fd, F_SETFL, O_NONBLOCK);
                fprintf(stderr, "[audio] pw-cat launched (pid %d)\n", (int)audio_pid);
            }
        }
    } else {
        fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 16 * 1024 * 1024);
    }

    if (pthread_create(&wt, NULL, write_thread_fn, NULL) != 0) { perror("pthread_create"); goto out; }
    wt_started = 1;

    for (int i = 0; i < NUM_TRANSFERS; i++) {
        uint8_t *buf = malloc(ISO_BUF_SIZE);
        xfers[i] = libusb_alloc_transfer(ISO_PACKETS_PER_URB);
        if (!buf || !xfers[i]) { fprintf(stderr, "alloc failed\n"); goto stop; }
        libusb_fill_iso_transfer(xfers[i], dev, EP_VIDEO, buf, ISO_BUF_SIZE,
                                 ISO_PACKETS_PER_URB, iso_callback, NULL, 1000);
        libusb_set_iso_packet_lengths(xfers[i], ISO_PACKET_SIZE);
        r = libusb_submit_transfer(xfers[i]);
        if (r < 0) {
            fprintf(stderr, "[usb] submit transfer %d: %s\n", i, libusb_error_name(r));
            free(xfers[i]->buffer);
            libusb_free_transfer(xfers[i]);
            xfers[i] = NULL;
            if (i < 4) goto stop;        /* too little buffering to be useful */
            fprintf(stderr, "[usb] continuing with %d queued transfers\n", i);
            break;
        }
        g_inflight++;
    }

    struct timeval t0, now, last;
    gettimeofday(&t0, NULL);
    last = t0;
    uint64_t last_ok = 0, last_bytes = 0, black_ok = (uint64_t)-1;
    int warned_nosignal = 0;
    double stat_every = virt ? 30.0 : 2.0;
    struct timeval black_t = t0;
    if (virt) push_black_frame();

    while (g_running) {
        struct timeval tv = {0, 100000};
        r = libusb_handle_events_timeout_completed(ctx, &tv, NULL);
        if (r < 0 && r != LIBUSB_ERROR_INTERRUPTED) {
            fprintf(stderr, "handle_events: %s\n", libusb_error_name(r));
            break;
        }
        gettimeofday(&now, NULL);

        /* No real frame for 200 ms: show black at 5 fps until the signal returns. */
        if (virt) {
            double bdt = (now.tv_sec - black_t.tv_sec) + (now.tv_usec - black_t.tv_usec) * 1e-6;
            if (st_frames_ok != black_ok) {
                black_ok = st_frames_ok;
                black_t  = now;
            } else if (bdt >= 0.2) {
                push_black_frame();
                black_t = now;
            }
        }

        double dt = (now.tv_sec - last.tv_sec) + (now.tv_usec - last.tv_usec) * 1e-6;
        if (dt >= stat_every) {
            double since = (now.tv_sec - t0.tv_sec) + (now.tv_usec - t0.tv_usec) * 1e-6;
            if (st_usb_bytes == 0 && since > 2.0 && !warned_nosignal) {
                fprintf(stderr, "[warn] device sends no data: is an HDMI source connected and on?\n");
                warned_nosignal = 1;
            }
            fprintf(stderr, "[stat] %.1f fps  %.1f MB/s  ok=%llu bad=%llu ring_drop=%llu resync=%llu iso_err=%llu audio_drop=%llu\n",
                    (st_frames_ok - last_ok) / dt,
                    (st_usb_bytes - last_bytes) / dt / 1e6,
                    (unsigned long long)st_frames_ok, (unsigned long long)st_frames_bad,
                    (unsigned long long)st_frames_dropped_ring, (unsigned long long)st_resyncs,
                    (unsigned long long)st_iso_err_pkts, (unsigned long long)st_audio_drops);
            last = now; last_ok = st_frames_ok; last_bytes = st_usb_bytes;
        }
    }

stop:
    g_running = 0;
    for (int i = 0; i < NUM_TRANSFERS; i++)
        if (xfers[i]) libusb_cancel_transfer(xfers[i]);
    while (g_inflight > 0) {
        struct timeval tv = {0, 100000};
        if (libusb_handle_events_timeout_completed(ctx, &tv, NULL) < 0) break;
    }
    for (int i = 0; i < NUM_TRANSFERS; i++) {
        if (xfers[i]) { free(xfers[i]->buffer); libusb_free_transfer(xfers[i]); }
    }
    libusb_set_interface_alt_setting(dev, IFACE_VIDEO, 0);
    ret = 0;

    fprintf(stderr, "[done] frames ok=%llu bad=%llu ring_drop=%llu resyncs=%llu iso_err=%llu empty=%llu audio=%llu bytes\n",
            (unsigned long long)st_frames_ok, (unsigned long long)st_frames_bad,
            (unsigned long long)st_frames_dropped_ring, (unsigned long long)st_resyncs,
            (unsigned long long)st_iso_err_pkts, (unsigned long long)st_empty_pkts,
            (unsigned long long)st_audio_bytes);

out:
    if (wt_started) {
        pthread_mutex_lock(&ring_mutex);
        ring_done = 1;
        pthread_mutex_unlock(&ring_mutex);
        pthread_cond_signal(&ring_not_empty);
        pthread_join(wt, NULL);
    }
    if (dev) {
        if (claimed) libusb_release_interface(dev, IFACE_VIDEO);
        libusb_close(dev);
    }
    libusb_exit(ctx);
    if (audio_out) fclose(audio_out);
    if (audio_pid > 0) {
        /* pw-cat only notices EOF when PipeWire schedules it, which never
         * happens for an unused (suspended) source; terminate it instead. */
        if (audio_fd >= 0) close(audio_fd);
        kill(audio_pid, SIGTERM);
        while (waitpid(audio_pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    if (ffplay_pid > 0) {
        close(STDOUT_FILENO);            /* EOF -> ffplay exits */
        while (waitpid(ffplay_pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    return ret;
}
