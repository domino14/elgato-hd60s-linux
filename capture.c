#define _GNU_SOURCE
/*
 * elgato-hd60s -- userspace capture driver for Elgato Game Capture HD60 S
 * USB ID: 0fd9:0074
 *
 * Reverse-engineered from USB traffic captures.
 * Video format: raw YUY2 (YUYV 4:2:2), written to stdout.
 *
 * Usage:
 *   ./capture | ffplay -f rawvideo -pixel_format yuyv422 -framerate 60 -video_size 1920x1080 -i -
 *
 * Build:
 *   gcc -O2 -o capture capture.c $(pkg-config --cflags --libs libusb-1.0)
 */

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>

#include "init_sequence.h"

#define VID                 0x0fd9
#define PID                 0x0074

#define IFACE_VIDEO         0
#define ALT_ISO             2       /* alt setting 2 */

#define EP_VIDEO            0x83    /* EP3 IN isochronous */

#define LINE_PIXELS  1920
#define LINE_BYTES   (LINE_PIXELS * 2)   /* 3840 */

/* Frame buffer height: maximum lines we can store.  Must be >= any resolution
 * the device will ever send (1080p = 1080 lines).  The actual output height
 * and lsync trigger count are measured at runtime during CAL_SECS. */
#define FRAME_BUF_HEIGHT    1200
#define OUTPUT_HEIGHT       FRAME_BUF_HEIGHT   /* alias kept for static arrays */

/* Device sends ~941–949 active lines per frame (verified from Windows pcap).
 * Windows OBS upscales to 1080p in software; we output at native resolution. */
#define TARGET_FPS          60.0
#define NATIVE_HEIGHT       944   /* median active lines/frame seen in Windows pcap */
#define MIN_FRAME_LINES     900   /* below this → false VBI detection, ignore */
#define MAX_FRAME_LINES     960   /* above this → force push (missed VBI fallback) */

static volatile int g_output_lines = NATIVE_HEIGHT;
static volatile int g_calibrated   = 1;     /* always ready — no calibration needed */

#define ISO_PACKETS_PER_URB  8
#define ISO_PACKET_SIZE      32768
#define ISO_BUF_SIZE         (ISO_PACKETS_PER_URB * ISO_PACKET_SIZE)
#define NUM_TRANSFER_BUFS    8

static volatile int g_running = 1;
static uint64_t g_bytes_received = 0;
static uint64_t g_usb_bytes_raw = 0;   /* raw bytes from ISO packets, before parsing */

/* raw dump of first 65536 bytes from ISO stream */
#define DUMP_SIZE 65536
static uint8_t  g_dump_buf[DUMP_SIZE];
static uint32_t g_dump_len = 0;

/* frame-locked output state */
static uint8_t   s_frame_buf[FRAME_BUF_HEIGHT * LINE_BYTES];
static int       s_frame_lines  = 0;   /* lines accumulated this frame */
static int       s_frame_lsyncs = 0;   /* lsyncs accumulated this frame */
static uint64_t  s_frames_out   = 0;   /* frames flushed to stdout */

/* ── Write thread ring buffer ────────────────────────────────────────────── */
/*
 * The USB isochronous callback must never block on fwrite, or isochronous
 * packets are silently lost, causing lsync drops and vertical rolling.
 * We decouple capture from output with a 4-frame ring buffer: the USB path
 * does a fast memcpy, the write thread does the blocking fwrite.
 */
#define RING_BUFS 4
static uint8_t  ring_frames[RING_BUFS][FRAME_BUF_HEIGHT * LINE_BYTES];
static int      ring_head = 0;   /* producer increments */
static int      ring_tail = 0;   /* consumer increments */
static int      ring_done = 0;   /* set to 1 at shutdown */
static pthread_mutex_t ring_mutex     = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  ring_not_empty = PTHREAD_COND_INITIALIZER;

static void *write_thread_fn(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&ring_mutex);
        while (ring_head == ring_tail && !ring_done)
            pthread_cond_wait(&ring_not_empty, &ring_mutex);
        if (ring_head == ring_tail) {   /* done and empty */
            pthread_mutex_unlock(&ring_mutex);
            break;
        }
        int slot = ring_tail % RING_BUFS;
        ring_tail++;
        pthread_mutex_unlock(&ring_mutex);

        fwrite(ring_frames[slot], 1, (size_t)g_output_lines * LINE_BYTES, stdout);
        fflush(stdout);
    }
    return NULL;
}

/* Push completed frame to ring; drop silently if ring is full. */
static void push_frame(void)
{
    pthread_mutex_lock(&ring_mutex);
    if (ring_head - ring_tail >= RING_BUFS) {
        pthread_mutex_unlock(&ring_mutex);
        return;   /* full — drop frame rather than blocking */
    }
    int slot = ring_head % RING_BUFS;
    pthread_mutex_unlock(&ring_mutex);

    /* Copy to slot while unlocked — safe: only one producer, slot is ours
     * until we commit by incrementing ring_head below. */
    memcpy(ring_frames[slot], s_frame_buf, (size_t)g_output_lines * LINE_BYTES);

    pthread_mutex_lock(&ring_mutex);
    ring_head++;
    pthread_mutex_unlock(&ring_mutex);
    pthread_cond_signal(&ring_not_empty);
}

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ── Init sequence ───────────────────────────────────────────────────────── */

static void send_init_sequence(libusb_device_handle *dev)
{
    uint8_t rxbuf[16];
    int errors = 0;

    fprintf(stderr, "[init] sending %d commands...\n", INIT_SEQ_LEN);

    for (int i = 0; i < INIT_SEQ_LEN; i++) {
        const struct init_cmd *c = &init_sequence[i];
        uint8_t bmRequestType = LIBUSB_REQUEST_TYPE_VENDOR |
                                LIBUSB_RECIPIENT_DEVICE |
                                LIBUSB_ENDPOINT_OUT;
        int r = libusb_control_transfer(dev, bmRequestType,
                    c->brequest, c->wvalue, 0,
                    (unsigned char *)c->data, c->len, 2000);
        if (r < 0) {
            if (errors++ < 10)
                fprintf(stderr, "  [%d] cmd 0x%02x reg 0x%04x len %d: %s\n",
                        i, c->brequest, c->wvalue, c->len,
                        libusb_error_name(r));
        }

        /* After every write to REG_CMD (0x5066) that uses bRequest=0xc0,
         * Windows reads back 1–3 bytes as an ACK. We mimic that but
         * ignore the result. */
        if (c->brequest == 0xc0 && c->wvalue == 0x5066 && c->len > 0) {
            uint8_t acklen = (c->len == 5) ? 3 : 1; /* 5-byte writes → 3-byte ack */
            libusb_control_transfer(dev,
                LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
                0xc0, 0x5066, 0, rxbuf, acklen, 500);
        }

        if ((i & 0xff) == 0)
            fprintf(stderr, "\r[init] %d/%d...", i, INIT_SEQ_LEN);
    }
    fprintf(stderr, "\r[init] done (%d errors)          \n", errors);
}

/* ── Video parser ────────────────────────────────────────────────────────── */

/*
 * Device line format:
 *   [3840 bytes YUY2] [ff 00 00 80]                        -- short sync (4 bytes)
 *   [3840 bytes YUY2] [ff 00 ff 02 <8 bytes> ff 00 00 80]  -- long sync (16 bytes)
 *
 * The pattern ff 00 00 80 cannot appear in limited-range YUV video:
 *   0xff = luma 255, above valid max of 235
 *   0x00 = chroma 0, below valid min of 16
 * Full 4-byte pattern matching avoids all false positives.
 *
 * Implementation: 3-byte lookahead delay buffer. We hold back 3 bytes
 * before committing them to the line buffer, so we can detect the full
 * 4-byte sync pattern before any bytes are committed.
 */

static uint8_t  s_line_buf[LINE_BYTES];
static int      s_line_pos   = 0;
static int      s_synced     = 0;
static int      s_in_sync    = 0;
static uint8_t  s_sync_prev  = 0;
static int      s_sync_count = 0;
static uint64_t s_line_count = 0;
static uint64_t s_long_syncs = 0;
static int      s_in_vbi     = 0;   /* 1 while in vertical blanking interval */

/* 3-byte lookahead delay */
static uint8_t  s_delay[3]   = {0};
static int      s_delay_len  = 0;

/* long-sync payload capture */
static uint8_t  s_lsync_payload[12] = {0};
static int      s_lsync_payload_len = 0;

/* lines-between-long-syncs histogram (0..2047, overflow bucket at 2048) */
#define HIST_MAX 2049
static uint32_t s_lsync_hist[HIST_MAX] = {0};
static uint64_t s_lines_since_lsync = 0;

/* skipped lines (sync fired but line_pos != LINE_BYTES) */
static uint64_t s_skipped_lines = 0;
static uint64_t s_skipped_short = 0;
static uint64_t s_skipped_long  = 0;

/* diagnostic counters */
static uint64_t s_iso_errors    = 0;   /* iso packets with bad status */
static uint64_t s_false_vbi     = 0;   /* frame_boundary() rejected by MIN_FRAME_LINES */
static uint64_t s_forced_push   = 0;   /* frame pushes from MAX_FRAME_LINES fallback */
static uint64_t s_lsync_bailouts = 0;  /* s_in_sync abandoned (count > 24) */

/* per-frame trigger type: 'L'=long sync, 'S'=short sync, 'M'=max fallback */
static char s_push_trigger = '?';


/* wall-clock timestamps of first and last emitted line */
static struct timeval s_first_line_tv = {0, 0};
static struct timeval s_last_line_tv  = {0, 0};


static inline void commit_byte(uint8_t b)
{
    if (s_synced && s_line_pos < LINE_BYTES)
        s_line_buf[s_line_pos++] = b;
}

/* Push the accumulated active lines as one output frame.
 * Pads any unfilled lines (below g_output_lines) with YUY2 black.
 * Callers must ALWAYS set s_in_vbi=1 after calling this — VBI mode is
 * entered regardless of whether a frame was pushed. */
static void frame_boundary(void)
{
    if (!s_synced || s_frame_lines == 0)
        return;
    if (s_frame_lines < MIN_FRAME_LINES) {
        s_false_vbi++;
        s_frame_lines = 0;   /* discard partial frame — start fresh next frame */
        return;
    }

    /* Pad remaining lines with YUY2 black (limited range: Y=0x10, Cb=Cr=0x80) */
    for (int fl = s_frame_lines; fl < g_output_lines; fl++) {
        uint8_t *row = s_frame_buf + (size_t)fl * LINE_BYTES;
        for (int j = 0; j < LINE_BYTES; j += 4) {
            row[j+0] = 0x10;
            row[j+1] = 0x80;
            row[j+2] = 0x10;
            row[j+3] = 0x80;
        }
    }

    push_frame();

    if (s_frames_out < 10 || (s_frames_out % 60) == 0) {
        double active_dt = (s_last_line_tv.tv_sec  - s_first_line_tv.tv_sec) +
                           (s_last_line_tv.tv_usec - s_first_line_tv.tv_usec) * 1e-6;
        double lines_per_sec = (active_dt > 0.1) ? s_line_count / active_dt : 0;
        fprintf(stderr, "[frame #%llu] active=%d/%d  trigger=%c  false_vbi=%llu  forced=%llu  total_lines=%llu  %.1f lines/sec\n",
                (unsigned long long)s_frames_out, s_frame_lines, g_output_lines,
                s_push_trigger,
                (unsigned long long)s_false_vbi,
                (unsigned long long)s_forced_push,
                (unsigned long long)s_line_count, lines_per_sec);
    }

    s_frames_out++;
    s_frame_lines  = 0;
    s_frame_lsyncs = 0;
}

/* Called once per complete active (V=0) line (after sync detection).
 * Copies line to frame buffer.  Frame is pushed by frame_boundary() at the
 * VBI→active transition, not here.
 * Must not be called for VBI lines (check s_in_vbi before calling). */
static inline void commit_line(void)
{
    if (s_in_vbi) return;   /* safety: ignore blanking lines */
    if (s_frame_lines < g_output_lines)
        memcpy(s_frame_buf + (size_t)s_frame_lines * LINE_BYTES, s_line_buf, LINE_BYTES);
    s_frame_lines++;
    g_bytes_received += LINE_BYTES;
    s_line_count++;
    s_lines_since_lsync++;
    gettimeofday(&s_last_line_tv, NULL);
    if (s_first_line_tv.tv_sec == 0) s_first_line_tv = s_last_line_tv;

    /* Fallback: if VBI was missed entirely, force a frame push */
    if (s_frame_lines >= MAX_FRAME_LINES) {
        s_forced_push++;
        s_push_trigger = 'M';
        frame_boundary();
        /* Don't set s_in_vbi — no real VBI seen, keep accumulating active */
    }
}

static void parse_and_emit(const uint8_t *src, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        uint8_t b = src[i];

        /* ── eat sync bytes until terminal SAV byte ── */
        if (s_in_sync) {
            /* capture payload bytes (up to 12) for diagnostics */
            if (s_lsync_payload_len < 12)
                s_lsync_payload[s_lsync_payload_len++] = b;

            s_sync_count++;

            /* Positions 5–12 are the 8-byte payload: skip without checking.
             * The Windows pcap shows payload is always all-zeros or all-ff
             * halves — no 00 80 or 00 ab — but we skip anyway for safety. */
            if (s_sync_count <= 12) {
                s_sync_prev = b;
                continue;
            }

            /* Positions 13+: looking for TRS terminator ff 00 00 XY */
            if (s_sync_prev == 0x00 && (b == 0x80 || b == 0xab)) {
                s_long_syncs++;

                int sav_vbi = (b == 0xab);  /* V=1 → VBI;  V=0 → active */

                if (sav_vbi && !s_in_vbi) {
                    /* Long sync ends in VBI SAV: active→VBI transition.
                     * Always enter VBI mode — frame_boundary() handles
                     * whether to push or discard the partial frame. */
                    s_push_trigger = 'L';
                    frame_boundary();
                    s_in_vbi = 1;
                } else if (!sav_vbi) {
                    /* Active SAV: leaving VBI (if we were in it). */
                    s_in_vbi = 0;
                }

                /* record lines-between-long-syncs in histogram */
                uint64_t bucket = s_lines_since_lsync;
                if (bucket >= HIST_MAX) bucket = HIST_MAX - 1;
                s_lsync_hist[bucket]++;
                s_lines_since_lsync = 0;

                s_in_sync    = 0;
                s_sync_count = 0;
                s_sync_prev  = 0;
                s_line_pos   = 0;
                s_synced     = 1;
                s_delay_len  = 0;
                s_lsync_payload_len = 0;

                s_frame_lsyncs++;
            } else if (s_sync_count > 24) {
                /* Bailout: malformed or corrupted long sync (e.g. bit-flipped
                 * SAV byte).  Abandon and let normal parsing resume. */
                s_lsync_bailouts++;
                s_in_sync    = 0;
                s_sync_count = 0;
                s_sync_prev  = 0;
                s_delay_len  = 0;
                s_lsync_payload_len = 0;
                /* s_line_pos left as-is — position guard will resync */
            } else {
                s_sync_prev = b;
            }
            continue;
        }

        /* ── fill delay buffer until we have 3 bytes ── */
        if (s_delay_len < 3) {
            s_delay[s_delay_len++] = b;
            continue;
        }

        /* ── check if delay[0..2] + b forms a sync pattern ── */
        /*
         * Position guard for false-positive protection (full-range YUV can
         * contain the sync byte sequences as valid pixel data):
         *  – Short syncs (ff 00 00 XY): only accept at LINE_BYTES.
         *  – Long syncs  (ff 00 ff 02): accept at LINE_BYTES OR at 0.
         *    The "at 0" case handles the real-world pattern where the last
         *    active line ends with a SHORT sync (resetting s_line_pos to 0),
         *    and the very next marker is the first VBI long sync.
         */
        if (s_delay[0] == 0xff && s_delay[1] == 0x00 &&
            s_delay[2] == 0x00 && (b == 0x80 || b == 0xab)) {
            /* short sync: ff 00 00 80 (active V=0) or ff 00 00 ab (VBI V=1) */
            int sav_vbi = (b == 0xab);

            if (!s_synced || s_line_pos == LINE_BYTES) {
                if (s_synced) {
                    if (!sav_vbi && !s_in_vbi) {
                        /* Active SAV: commit the completed active line */
                        commit_line();
                    } else if (sav_vbi && !s_in_vbi) {
                        /* First VBI short sync after active video:
                         * commit the last active line, then push the frame.
                         * Always enter VBI mode regardless of frame push. */
                        commit_line();
                        s_push_trigger = 'S';
                        frame_boundary();
                        s_in_vbi = 1;
                    }
                    /* sav_vbi && s_in_vbi: another VBI line, nothing to commit */
                }
                if (!sav_vbi) s_in_vbi = 0;   /* active SAV → leave VBI */
                s_line_pos  = 0;
                s_synced    = 1;
                s_delay_len = 0;
            } else {
                /* false positive mid-line — treat as video */
                commit_byte(s_delay[0]);
                s_delay[0] = s_delay[1];
                s_delay[1] = s_delay[2];
                s_delay[2] = b;
            }

        } else if (s_delay[0] == 0xff && s_delay[1] == 0x00 &&
                   s_delay[2] == 0xff && b == 0x02) {
            /* long sync: ff 00 ff 02 ... ff 00 00 XY */
            if (!s_synced || s_line_pos == LINE_BYTES || s_line_pos == 0) {
                /* Accept at: (a) initial lock, (b) line boundary, (c) after
                 * a short sync (pos reset to 0) — the typical VBI-start case. */
                if (s_synced && s_line_pos == LINE_BYTES && !s_in_vbi)
                    commit_line();
                s_line_pos   = 0;
                s_in_sync    = 1;
                s_sync_count = 4;
                s_sync_prev  = 0x02;
                s_delay_len  = 0;
                s_lsync_payload_len = 0;
            } else {
                /* false positive mid-line — treat as video */
                commit_byte(s_delay[0]);
                s_delay[0] = s_delay[1];
                s_delay[1] = s_delay[2];
                s_delay[2] = b;
            }

        } else {
            /* not a sync — commit oldest delay byte and shift */
            commit_byte(s_delay[0]);
            s_delay[0] = s_delay[1];
            s_delay[1] = s_delay[2];
            s_delay[2] = b;
        }
    }
}

/* ── ISO transfer ────────────────────────────────────────────────────────── */

static void LIBUSB_CALL iso_callback(struct libusb_transfer *t)
{
    if (!g_running) {
        free(t->buffer);
        libusb_free_transfer(t);
        return;
    }

    if (t->status == LIBUSB_TRANSFER_COMPLETED ||
        t->status == LIBUSB_TRANSFER_TIMED_OUT) {
        for (int i = 0; i < t->num_iso_packets; i++) {
            struct libusb_iso_packet_descriptor *pkt = &t->iso_packet_desc[i];
            if (pkt->status != LIBUSB_TRANSFER_COMPLETED)
                s_iso_errors++;
            if (pkt->status == LIBUSB_TRANSFER_COMPLETED && pkt->actual_length > 0) {
                const uint8_t *data = libusb_get_iso_packet_buffer_simple(t, i);
                g_usb_bytes_raw += pkt->actual_length;
                if (g_dump_len < DUMP_SIZE) {
                    uint32_t copy = pkt->actual_length;
                    if (g_dump_len + copy > DUMP_SIZE) copy = DUMP_SIZE - g_dump_len;
                    memcpy(g_dump_buf + g_dump_len, data, copy);
                    g_dump_len += copy;
                }
                parse_and_emit(data, pkt->actual_length);
            }
        }
    } else if (t->status == LIBUSB_TRANSFER_NO_DEVICE) {
        g_running = 0;
        free(t->buffer);
        libusb_free_transfer(t);
        return;
    } else {
        static int err_count = 0;
        if (err_count++ < 5)
            fprintf(stderr, "[iso] transfer status: %s\n",
                    libusb_error_name(t->status));
    }

    if (g_running && libusb_submit_transfer(t) < 0) {
        g_running = 0;
        free(t->buffer);
        libusb_free_transfer(t);
    }
}

static struct libusb_transfer *make_iso_transfer(libusb_device_handle *dev)
{
    uint8_t *buf = malloc(ISO_BUF_SIZE);
    if (!buf) return NULL;

    struct libusb_transfer *t = libusb_alloc_transfer(ISO_PACKETS_PER_URB);
    if (!t) { free(buf); return NULL; }

    libusb_fill_iso_transfer(t, dev, EP_VIDEO,
                             buf, ISO_BUF_SIZE,
                             ISO_PACKETS_PER_URB,
                             iso_callback, NULL, 5000);
    libusb_set_iso_packet_lengths(t, ISO_PACKET_SIZE);
    return t;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    libusb_context *ctx = NULL;
    libusb_device_handle *dev = NULL;
    struct libusb_transfer *transfers[NUM_TRANSFER_BUFS];
    int r, i;
    int need_ffplay = isatty(STDOUT_FILENO);  /* auto-launch if stdout is a tty */
    pid_t ffplay_pid = -1;
    pthread_t wt;
    int wt_started = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    r = libusb_init(&ctx);
    if (r < 0) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(r));
        return 1;
    }

    libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING);

    dev = libusb_open_device_with_vid_pid(ctx, VID, PID);
    if (!dev) {
        fprintf(stderr, "Device %04x:%04x not found. Is it plugged in?\n", VID, PID);
        goto out;
    }
    fprintf(stderr, "[open] Elgato HD60 S found\n");

    libusb_set_auto_detach_kernel_driver(dev, 1);

    /* Reset to clear any state from a previous run. */
    r = libusb_reset_device(dev);
    if (r == LIBUSB_ERROR_NOT_FOUND) {
        libusb_close(dev);
        usleep(500000);
        dev = libusb_open_device_with_vid_pid(ctx, VID, PID);
        if (!dev) { fprintf(stderr, "Device not found after reset\n"); goto out; }
        libusb_set_auto_detach_kernel_driver(dev, 1);
        fprintf(stderr, "[reset] reopened after re-enumeration\n");
    } else if (r < 0) {
        fprintf(stderr, "[reset] %s (continuing)\n", libusb_error_name(r));
    }

    r = libusb_claim_interface(dev, IFACE_VIDEO);
    if (r < 0) {
        fprintf(stderr, "claim interface: %s\n", libusb_error_name(r));
        goto out;
    }

    /* Send full cold-start init sequence at alt setting 0 (no bandwidth) */
    send_init_sequence(dev);

    /* Now switch to isochronous alt setting */
    fprintf(stderr, "[init] switching to alt setting %d\n", ALT_ISO);
    r = libusb_set_interface_alt_setting(dev, IFACE_VIDEO, ALT_ISO);
    if (r < 0) {
        fprintf(stderr, "set_interface_alt_setting: %s\n", libusb_error_name(r));
        goto out;
    }

    /* Allocate and queue ISO transfers */
    for (i = 0; i < NUM_TRANSFER_BUFS; i++) {
        transfers[i] = make_iso_transfer(dev);
        if (!transfers[i]) {
            fprintf(stderr, "failed to allocate transfer %d\n", i);
            goto out;
        }
        r = libusb_submit_transfer(transfers[i]);
        if (r < 0) {
            fprintf(stderr, "submit transfer %d: %s\n", i, libusb_error_name(r));
            goto out;
        }
    }


    struct timeval stream_start, stream_end;
    gettimeofday(&stream_start, NULL);

    struct timeval tv = {0, 100000};
    while (g_running) {
        r = libusb_handle_events_timeout(ctx, &tv);
        if (r < 0 && r != LIBUSB_ERROR_INTERRUPTED) {
            fprintf(stderr, "handle_events: %s\n", libusb_error_name(r));
            break;
        }

        /* One-time post-calibration setup: launch ffplay and write thread */
        if (g_calibrated && !wt_started) {
            wt_started = 1;

            if (need_ffplay) {
                /* Fork ffplay now that we know the calibrated video size */
                int pfd[2];
                if (pipe(pfd) < 0) { perror("pipe"); g_running = 0; break; }
                ffplay_pid = fork();
                if (ffplay_pid < 0) { perror("fork"); g_running = 0; break; }
                if (ffplay_pid == 0) {
                    close(pfd[1]);
                    dup2(pfd[0], STDIN_FILENO);
                    close(pfd[0]);
                    char vsize[32];
                    snprintf(vsize, sizeof(vsize), "1920x%d", g_output_lines);
                    execlp("ffplay", "ffplay",
                           "-f", "rawvideo",
                           "-pixel_format", "yuyv422",
                           "-video_size", vsize,
                           "-framerate", "60",
                           "-i", "-", NULL);
                    perror("execlp ffplay");
                    _exit(1);
                }
                close(pfd[0]);
                fcntl(pfd[1], F_SETPIPE_SZ, 16 * 1024 * 1024);
                dup2(pfd[1], STDOUT_FILENO);
                close(pfd[1]);
                fprintf(stderr, "[ffplay] launched (pid %d) — Ctrl+C to stop\n",
                        (int)ffplay_pid);
            } else {
                /* User is piping manually; enlarge the pipe buffer */
                fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 16 * 1024 * 1024);
            }

            fprintf(stderr,
                "[stream] running — to preview:\n"
                "  ./capture | ffplay -f rawvideo -pixel_format yuyv422"
                " -framerate 60 -video_size 1920x%d -i -\n"
                "  (Ctrl+C to stop)\n", g_output_lines);

            /* Start write thread — fwrite now happens off the USB callback */
            if (pthread_create(&wt, NULL, write_thread_fn, NULL) != 0) {
                perror("pthread_create");
                g_running = 0;
                break;
            }
        }
    }

    /* Stop write thread — drain remaining frames then exit */
    if (wt_started) {
        pthread_mutex_lock(&ring_mutex);
        ring_done = 1;
        pthread_mutex_unlock(&ring_mutex);
        pthread_cond_signal(&ring_not_empty);
        pthread_join(wt, NULL);
    }

    gettimeofday(&stream_end, NULL);
    double elapsed = (stream_end.tv_sec  - stream_start.tv_sec) +
                     (stream_end.tv_usec - stream_start.tv_usec) * 1e-6;
    double lines_per_sec = s_line_count / elapsed;

    /* accurate rate: first line to last line (excludes startup dead time) */
    double active_elapsed = (s_last_line_tv.tv_sec  - s_first_line_tv.tv_sec) +
                            (s_last_line_tv.tv_usec - s_first_line_tv.tv_usec) * 1e-6;
    double active_lps = (s_line_count > 1) ? (s_line_count - 1) / active_elapsed : 0;

    fprintf(stderr, "\n[done] %.2f MB received, %llu lines, %llu long-syncs, %llu frames out\n",
            (double)g_bytes_received / (1024.0 * 1024.0),
            (unsigned long long)s_line_count,
            (unsigned long long)s_long_syncs,
            (unsigned long long)s_frames_out);

    double usb_mb = g_usb_bytes_raw / (1024.0 * 1024.0);
    double usb_mbs = usb_mb / active_elapsed;
    /* At 1125 lines/frame × 3844 bytes/line × 60fps = 259.5 MB/s expected */
    double implied_fps_at_1125 = (g_usb_bytes_raw / 3844.0) / 1125.0 / active_elapsed;
    fprintf(stderr, "[usb]  raw USB: %.2f MB total, %.1f MB/s  →  %.2f fps×1125 lines\n",
            usb_mb, usb_mbs, implied_fps_at_1125);
    fprintf(stderr, "[rate] loop: %.1f lines/sec over %.2fs  active: %.1f lines/sec over %.2fs\n",
            lines_per_sec, elapsed, active_lps, active_elapsed);
    fprintf(stderr, "[rate] at 60fps:    %.2f lines/frame\n", active_lps / 60.0);
    fprintf(stderr, "[rate] at 59.94fps: %.2f lines/frame\n", active_lps / 59.94);
    double lsync_fps = s_long_syncs / active_elapsed;
    fprintf(stderr, "[rate] lsyncs: %.1f/sec  →  %.2f lsyncs/frame at 60fps\n",
            lsync_fps, lsync_fps / 60.0);
    fprintf(stderr, "[cal]  output: %d lines/frame (native height, VBI-triggered)\n",
            g_output_lines);
    fprintf(stderr, "[skip] skipped lines (sync fired, buf incomplete): %llu total (%llu short, %llu long)\n",
            (unsigned long long)s_skipped_lines,
            (unsigned long long)s_skipped_short,
            (unsigned long long)s_skipped_long);
    fprintf(stderr, "[diag] iso_errors=%llu  false_vbi=%llu  forced_push=%llu  lsync_bailouts=%llu\n",
            (unsigned long long)s_iso_errors,
            (unsigned long long)s_false_vbi,
            (unsigned long long)s_forced_push,
            (unsigned long long)s_lsync_bailouts);

    /* write raw dump */
    FILE *df = fopen("/tmp/raw_dump.bin", "wb");
    if (df) { fwrite(g_dump_buf, 1, g_dump_len, df); fclose(df); }
    fprintf(stderr, "[dump] wrote %u bytes to /tmp/raw_dump.bin\n", g_dump_len);

    /* print histogram of lines-between-long-syncs */
    fprintf(stderr, "[hist] lines between consecutive long-syncs:\n");
    for (int h = 0; h < HIST_MAX; h++) {
        if (s_lsync_hist[h])
            fprintf(stderr, "  %4d lines: %u times%s\n",
                    h, s_lsync_hist[h],
                    h == HIST_MAX-1 ? " (overflow)" : "");
    }

out:
    if (dev) {
        libusb_release_interface(dev, IFACE_VIDEO);
        libusb_close(dev);
    }
    libusb_exit(ctx);

    if (ffplay_pid > 0) {
        fclose(stdout);   /* signals EOF to ffplay */
        waitpid(ffplay_pid, NULL, 0);
    }
    return 0;
}
