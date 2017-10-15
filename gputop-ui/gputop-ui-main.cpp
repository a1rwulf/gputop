/*
 * GPU Top
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>

#include "imgui.h"
#include "imgui_impl_gtk3_cogl.h"
#include "gputop-ui-multilines.h"
#include "gputop-ui-timeline.h"
#include "gputop-ui-topology.h"
#include "gputop-ui-utils.h"

#include "util/hash_table.h"
#include "util/list.h"

#include "gputop.pb-c.h"
#include "gputop-oa-counters.h"
#include "gputop-soup-network.h"
#include "gputop-util.h"

#include "oa-hsw.h"
#include "oa-bdw.h"
#include "oa-chv.h"
#include "oa-sklgt2.h"
#include "oa-sklgt3.h"
#include "oa-sklgt4.h"
#include "oa-bxt.h"
#include "oa-kblgt2.h"
#include "oa-kblgt3.h"
#include "oa-glk.h"
#include "oa-cflgt2.h"
#include "oa-cflgt3.h"
#include "oa-cnl.h"

/**/

struct window {
    struct list_head link;

    char name[128];
    bool opened;

    ImVec2 position;
    ImVec2 size;

    void (*display)(struct window*);
    void (*destroy)(struct window*);

    void (*reset)(struct window*);
};

struct i915_perf_chunk {
    struct list_head link;

    uint32_t refcount;

    uint32_t length;
    uint8_t data[];
};

struct process_info;

struct hw_context {
    char name[128];
    uint32_t hw_id;
    uint32_t timeline_row;

    uint32_t n_samples;

    uint64_t time_spent;

    struct list_head link;

    struct process_info *process;
};

struct accumulated_samples {
    struct list_head link;
    struct hw_context *context;

    /* Correlated in CPU clock */
    uint64_t timestamp_start;
    uint64_t timestamp_end;

    struct i915_perf_report {
        struct i915_perf_chunk *chunk;
        const struct drm_i915_perf_record_header *header;
    } start_report, end_report;

    struct gputop_cc_oa_accumulator accumulator;
};

struct cpu_stat {
    struct list_head link;

    Gputop__Message *stat;
};

struct stream {
    struct list_head link;

    int id;
    float fill;
};

struct perf_event {
    struct list_head link;

    char name[128];
    uint32_t event_id;

    struct list_head streams; /* struct perf_event_stream */
};

struct perf_event_data {
    struct {
        uint32_t type;
        uint16_t misc;
        uint16_t size;
    } header;
    uint64_t time;
    uint64_t value;
};

struct perf_event_stream {
    struct stream base;

    int cpu;
    struct perf_event *event;

    struct list_head link;

    struct perf_event_data *data;
};

struct perf_data_tracepoint {
    struct {
        uint32_t type;
        uint16_t misc;
        uint16_t size;
    } header;
    uint64_t time;
    uint32_t data_size;
    uint8_t  data[];
};

struct perf_tracepoint {
    struct list_head link;

    char name[128];
    uint32_t event_id;
    char *format;
    int idx;

    char uuid[20];

    struct {
        bool is_signed;
        int offset;
        int size;
        char name[80];
    } fields[20];
    int n_fields;

    int process_field;
    int hw_id_field;

    struct list_head streams; /* struct perf_tracepoint_stream */
};

struct perf_tracepoint_stream {
    struct stream base;

    int cpu;
    struct perf_tracepoint *tp;

    struct list_head link;
};

struct perf_tracepoint_data {
    struct list_head link;

    struct perf_tracepoint *tp;

    int cpu;
    struct perf_data_tracepoint data;
};

struct process_info {
    char cmd[256];
    char cmd_line[1024];
    uint32_t pid;
};

struct connection_state {
    char host_address[128];
    int host_port;
    gputop_connection_t *connection;
    char *connection_error;

    struct list_head streams;

    bool is_sampling;

    /**/
    Gputop__Message *features;
    Gputop__Message *tracepoint_info;

    struct hash_table *metrics_map;
    struct gputop_devinfo devinfo;

    int selected_uuid;

    /**/
    list_head cpu_stats;
    int n_cpu_stats;
    float cpu_stats_visible_timeline_s;
    int cpu_stats_sampling_period_ms;
    struct stream cpu_stats_stream;

    /**/
    const struct gputop_metric_set *metric_set;
    struct i915_perf_chunk *last_chunk;
    const struct drm_i915_perf_record_header *last_header;
    struct stream oa_stream;

    struct list_head free_samples;
    struct list_head i915_perf_chunks;

    /**/
    struct accumulated_samples *current_graph_sample;
    struct list_head graphs;
    int n_graphs;
    float oa_visible_timeline_s;
    uint32_t oa_aggregation_period_ms;

    /**/
    struct accumulated_samples *current_timeline_sample;
    struct list_head timelines;
    int n_timelines;
    uint32_t last_hw_id;

    struct hash_table *hw_contexts_table;
    struct list_head hw_contexts;

    /**/
    struct hash_table *perf_tracepoints_uuid_table;
    struct hash_table *perf_tracepoints_name_table;
    struct hash_table *perf_tracepoints_stream_table;
    struct list_head perf_tracepoints;
    struct list_head perf_tracepoints_data;

    /**/
    struct hash_table *perf_events_stream_table;
    struct list_head perf_events;

    /**/
    struct hash_table *processes_table;

    /**/
    struct {
        int level;
        char *msg;
    } messages[100];
    int start_message;
    int n_messages;

    /**/
    uint32_t stream_id;

    /**/
    void *temporary_buffer;
    size_t temporary_buffer_size;
};

struct i915_perf_window_counter {
    struct list_head link;

    const struct gputop_metric_set_counter *counter;
    double latest_max;
};

struct i915_perf_window {
    struct window base;

    struct list_head link;
    struct list_head counters;
};

struct timeline_window {
    struct window base;

    uint64_t zoom_start, zoom_length;
    struct accumulated_samples selected_samples;
    struct hw_context selected_context;

    struct perf_tracepoint tracepoint;
    uint64_t tracepoint_selected_ts;

    struct window reports_window;
};

static struct {
    /**/
    struct connection_state connection_state;

    ImColor cpu_colors[100];

    /* UI */
    struct list_head windows;
    struct list_head i915_perf_windows;

    struct window main_window;
    struct window log_window;
    struct window style_editor_window;
    struct window report_window;
    struct window streams_window;
    struct window tracepoints_window;
    struct timeline_window timeline_window;

    ImVec4 clear_color;
} context;

static const struct gputop_i915_perf_configuration i915_perf_config = {
    true, /* oa_reports */
    true, /* cpu_timestamps */
    true, /* gpu_timestamps */
};

/**/

static void
generate_uuid(struct connection_state *state, char *out, size_t size, void *ptr)
{
    snprintf(out, size, "%p", ptr);
}

/**/

struct protobuf_msg_closure;

static void
send_pb_message(ProtobufCMessage *pb_message)
{
    struct connection_state *state = &context.connection_state;

    if (!state->connection)
        return;

    size_t len = protobuf_c_message_get_packed_size(pb_message);
    uint8_t *data = (uint8_t *) malloc(len);
    protobuf_c_message_pack(pb_message, data);
    gputop_connection_send(state->connection, data, len);
    free(data);
}

/**/

static void
hide_window(struct window *win)
{
    /* NOP */
}

/**/

static void *
ensure_temporary_buffer(size_t size)
{
    struct connection_state *state = &context.connection_state;

    if (state->temporary_buffer_size < size) {
        state->temporary_buffer_size = size;
        state->temporary_buffer = realloc(state->temporary_buffer, size);
    }

    return state->temporary_buffer;
}

#define ensure_plot_accumulator(n_plot) \
    ((float *) ensure_temporary_buffer(n_plot * sizeof(float)))

#define ensure_timeline_names(n_names) \
    ((char **) ensure_temporary_buffer(n_names * sizeof(char *)))

/**/

static struct process_info *
get_process_info(struct connection_state *state, uint32_t pid)
{
    struct hash_entry *entry =
        pid == 0 ? NULL :
        _mesa_hash_table_search(state->processes_table, (void *)(uintptr_t)pid);
    if (entry || pid == 0)
        return entry ? ((struct process_info *) entry->data) : NULL;

    struct process_info *info = (struct process_info *) calloc(1, sizeof(*info));
    info->pid = pid;
    snprintf(info->cmd, sizeof(info->cmd), "<unknown>");
    _mesa_hash_table_insert(state->processes_table, (void *)(uintptr_t)pid, info);

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_GET_PROCESS_INFO;
    request.get_process_info = pid;
    send_pb_message(&request.base);

    return info;
}

static void
update_hw_contexts_process_info(struct connection_state *state,
                                struct process_info *process)
{
    list_for_each_entry(struct hw_context, context, &state->hw_contexts, link) {
        if (context->process != process)
            continue;

        snprintf(context->name, sizeof(context->name),
                 "%s id=0x%x", process->cmd, context->hw_id);
    }
}

/**/

static void
put_i915_perf_chunk(struct i915_perf_chunk *chunk)
{
    if (!chunk || --chunk->refcount)
        return;

    // g_message("free chunk=%p", chunk);

    list_del(&chunk->link);
    free(chunk);
}

static struct i915_perf_chunk *
get_i915_perf_chunk(struct connection_state *state,
                    const uint8_t *data, size_t len)
{
    struct i915_perf_chunk *chunk =
        (struct i915_perf_chunk *) malloc(len + sizeof(*chunk));

    memcpy(chunk->data, data, len);
    chunk->length = len;

    chunk->refcount = 1;
    list_addtail(&chunk->link, &state->i915_perf_chunks);

    return chunk;
}

static struct i915_perf_chunk *
ref_i915_perf_chunk(struct i915_perf_chunk *chunk)
{
    chunk->refcount++;
    return chunk;
}

/**/

static void
open_stream(struct stream *stream,
            struct connection_state *state,
            Gputop__OpenStream *pb_open_stream)
{
    stream->id = pb_open_stream->id = state->stream_id++;
    list_add(&stream->link, &state->streams);

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_OPEN_STREAM;
    request.open_stream = pb_open_stream;

    send_pb_message(&request.base);
}

static void
close_stream(struct stream *stream)
{
    if (stream->id == 0)
        return;

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_CLOSE_STREAM;
    request.close_stream = stream->id;
    send_pb_message(&request.base);

    list_del(&stream->link);
    memset(stream, 0, sizeof(*stream));
}

static bool
is_stream_opened(struct stream *stream)
{
    return stream->id != 0;
}

static struct stream *
find_stream(struct connection_state *state, uint32_t stream_id)
{
    list_for_each_entry(struct stream, stream, &state->streams, link) {
        if (stream->id == stream_id)
            return stream;
    }

    return NULL;
}

/**/

static struct perf_tracepoint *
new_tracepoint(struct connection_state *state, const char *name)
{
    struct perf_tracepoint *tp = (struct perf_tracepoint *) calloc(1, sizeof(*tp));

    tp->hw_id_field = tp->process_field = -1;
    tp->idx = list_length(&state->perf_tracepoints);
    list_inithead(&tp->streams);

    snprintf(tp->name, sizeof(tp->name), "%s", name);
    generate_uuid(state, tp->uuid, sizeof(tp->uuid), tp);

    list_addtail(&tp->link, &state->perf_tracepoints);
    _mesa_hash_table_insert(state->perf_tracepoints_uuid_table, tp->uuid, tp);
    _mesa_hash_table_insert(state->perf_tracepoints_name_table, tp->name, tp);

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.uuid = tp->uuid;
    request.req_case = GPUTOP__REQUEST__REQ_GET_TRACEPOINT_INFO;
    request.get_tracepoint_info = tp->name;
    send_pb_message(&request.base);

    return tp;
}

extern "C" {

union value {
    char *string;
    int integer;
};

struct parser_ctx {
    struct perf_tracepoint *tp;
    char *buffer;
    size_t len;
    int pos;
};

#define YY_CTX_LOCAL
#define YY_CTX_MEMBERS struct parser_ctx ctx;
#define YYSTYPE union value
#define YY_PARSE(T) static T
#define YY_INPUT(yy, buf, result, max)			\
{							\
    int c = yy->ctx.pos < yy->ctx.len ?                 \
        yy->ctx.buffer[yy->ctx.pos++] : EOF;            \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);          \
}

#include "tracepoint_format.leg.c"
}

static void
update_tracepoint(struct perf_tracepoint *tp,
                  const Gputop__TracepointInfo *info)
{
    assert(tp->n_fields == 0);

    tp->event_id = info->event_id;
    tp->format = strdup(info->sample_format);
    tp->hw_id_field = tp->process_field = -1;

    yycontext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ctx.tp = tp;
    ctx.ctx.buffer = tp->format;
    ctx.ctx.len = strlen(tp->format);
    if (yyparse(&ctx)) {
        /* Only use i915_gem_request_add for process correlation. */
        if (!strcmp(tp->name, "i915/i915_gem_request_add")) {
            for (int f = 0; f < tp->n_fields; f++) {
                if (!strcmp(tp->fields[f].name, "common_pid")) {
                    tp->process_field = f;
                } else if (!strcmp(tp->fields[f].name, "hw_id")) {
                    tp->hw_id_field = f;
                }
            }
        }
    } else
        tp->n_fields = 0;
}

static void
print_tracepoint_data(char *buf, size_t len, struct perf_tracepoint_data *data, bool include_name)
{
    struct perf_tracepoint *tp = data->tp;

    if (include_name) {
        int l = snprintf(buf, len, "%s: cpu:%i\n", data->tp->name, data->cpu);
        buf += l;
        len -= l;
    }

    for (int f = 0; f < tp->n_fields; f++) {
        const char *name = tp->fields[f].name;

        if (!strcmp("common_type", name) ||
            !strcmp("common_flags", name) ||
            !strcmp("common_preempt_count", name))
            continue;

        void *value_ptr = &data->data.data[tp->fields[f].offset];
        int l = 0;
        if (!strcmp("common_pid", name)) {
            uint32_t pid = *((uint32_t *) value_ptr);
            struct connection_state *state = &context.connection_state;
            struct hash_entry *entry =
                _mesa_hash_table_search(state->processes_table, (void *)(uintptr_t)pid);
            l = snprintf(buf, len, "pid = %u(%s)\n", pid,
                         entry ? ((struct process_info *)entry->data)->cmd : "<unknown>");
        } else {
            switch (tp->fields[f].size) {
            case 1:
                if (tp->fields[f].is_signed)
                    l = snprintf(buf, len, "%s = %hhd\n", name, *((int8_t *) value_ptr));
                else
                    l = snprintf(buf, len, "%s = %hhu\n", name, *((uint8_t *) value_ptr));
                break;
            case 2:
                if (tp->fields[f].is_signed)
                    l = snprintf(buf, len, "%s = %hd\n", name, *((int16_t *) value_ptr));
                else
                    l = snprintf(buf, len, "%s = %hu\n", name, *((uint16_t *) value_ptr));
                break;
            case 4:
                if (tp->fields[f].is_signed)
                    l = snprintf(buf, len, "%s = %d\n", name, *((int32_t *) value_ptr));
                else
                    l = snprintf(buf, len, "%s = %u\n", name, *((uint32_t *) value_ptr));
                break;
            case 8:
                if (tp->fields[f].is_signed)
                    l = snprintf(buf, len, "%s = %ld\n", name, *((int64_t *) value_ptr));
                else
                    l = snprintf(buf, len, "%s = %lu\n", name, *((uint64_t *) value_ptr));
                break;
            }
        }

        if (l > 0) {
            buf += l;
            len -= l;
        }
    }
}

static void
add_tracepoint_stream_data(struct perf_tracepoint_stream *stream, const uint8_t *data, size_t len)
{
    struct perf_tracepoint *tp = stream->tp;
    struct perf_tracepoint_data *tp_data =
        (struct perf_tracepoint_data *) malloc(sizeof(*tp_data) - sizeof(tp_data->data) + len);
    tp_data->tp = tp;
    tp_data->cpu = stream->cpu;
    memcpy(&tp_data->data, data, len);

    struct connection_state *state = &context.connection_state;

    /* Reunify the per cpu data into one single stream of tracepoints
     * sorted by time. */
    struct perf_tracepoint_data *tp_end_data =
        list_empty(&state->perf_tracepoints_data) ?
        NULL : list_last_entry(&state->perf_tracepoints_data, struct perf_tracepoint_data, link);
    while (tp_end_data && tp_end_data->data.time > tp_data->data.time) {
        tp_end_data = (tp_end_data->link.prev == &state->perf_tracepoints_data) ? NULL :
            LIST_ENTRY(struct perf_tracepoint_data, tp_end_data->link.prev, link);
    }

    list_add(&tp_data->link, tp_end_data ? &tp_end_data->link : &state->perf_tracepoints_data);

    /* Remove tracepoints outside the sampling window. */
    const uint64_t max_length = state->oa_visible_timeline_s * 1000000000ULL;
    struct perf_tracepoint_data *tp_start_data =
        list_first_entry(&state->perf_tracepoints_data, struct perf_tracepoint_data, link);
    tp_end_data = list_last_entry(&state->perf_tracepoints_data, struct perf_tracepoint_data, link);

    while ((tp_end_data->data.time - tp_start_data->data.time) > max_length) {
        list_del(&tp_start_data->link);
        free(tp_start_data);
        tp_start_data = list_first_entry(&state->perf_tracepoints_data, struct perf_tracepoint_data, link);
    }

    if (tp->process_field >= 0) {
        uint32_t pid = *((uint32_t *)&tp_data->data.data[tp->fields[tp->process_field].offset]);
        struct process_info *process = get_process_info(state, pid);

        if (tp->hw_id_field >= 0) {
            uint32_t hw_id = *((uint32_t *)&tp_data->data.data[tp->fields[tp->hw_id_field].offset]);
            struct hash_entry *entry =
                _mesa_hash_table_search(state->hw_contexts_table, (void *)(uintptr_t)hw_id);
            if (entry) {
                struct hw_context *context = (struct hw_context *) entry->data;
                if (context->process != process) {
                    context->process = process;
                    if (process->cmd_line[0] != '\0')
                        update_hw_contexts_process_info(state, process);
                }
            }
        }
    }
}

static void
close_perf_tracepoint(struct connection_state *state, struct perf_tracepoint *tp)
{
    list_for_each_entry_safe(struct perf_tracepoint_stream, stream, &tp->streams, link) {
        list_del(&stream->link);
        _mesa_hash_table_remove(state->perf_tracepoints_stream_table,
                                _mesa_hash_table_search(state->perf_tracepoints_stream_table,
                                                        (void *)(uintptr_t)stream->base.id));
        close_stream(&stream->base);
        free(stream);
    }
}

static void
open_perf_tracepoint(struct connection_state *state, struct perf_tracepoint *tp)
{
    close_perf_tracepoint(state, tp);

    Gputop__TracepointConfig pb_tp_config = GPUTOP__TRACEPOINT_CONFIG__INIT;
    pb_tp_config.pid = -1;
    pb_tp_config.id = tp->event_id;

    Gputop__OpenStream pb_stream = GPUTOP__OPEN_STREAM__INIT;
    pb_stream.overwrite = false;
    pb_stream.live_updates = true;
    pb_stream.type_case = GPUTOP__OPEN_STREAM__TYPE_TRACEPOINT;
    pb_stream.tracepoint = &pb_tp_config;

    for (int cpu = 0; cpu < state->features->features->n_cpus; cpu++) {
        pb_tp_config.cpu = cpu;

        struct perf_tracepoint_stream *stream =
            (struct perf_tracepoint_stream *) calloc(1, sizeof(struct perf_tracepoint_stream));
        stream->tp = tp;
        stream->cpu = cpu;
        open_stream(&stream->base, state, &pb_stream);

        list_add(&stream->link, &tp->streams);
        _mesa_hash_table_insert(state->perf_tracepoints_stream_table,
                                (void *)(uintptr_t)stream->base.id, stream);
    }
}

static void
destroy_perf_tracepoint(struct connection_state *state, struct perf_tracepoint *tp)
{
    close_perf_tracepoint(state, tp);
    if (tp->format)
        free(tp->format);
    list_del(&tp->link);
    free(tp);

    int idx = 0;
    list_for_each_entry(struct perf_tracepoint, ltp, &state->perf_tracepoints, link)
        ltp->idx = idx++;
}

static struct perf_tracepoint_stream *
find_perf_tracepoint_stream(struct connection_state *state, uint32_t stream_id)
{
    struct hash_entry *entry =
        _mesa_hash_table_search(state->perf_tracepoints_stream_table,
                                (void *)(uintptr_t)stream_id);

    return entry ? ((struct perf_tracepoint_stream *) entry->data) : NULL;
}

/**/

static void put_accumulated_sample(struct connection_state *state,
                                   struct accumulated_samples *samples);

static void
i915_perf_empty_samples(struct connection_state *state)
{
    list_for_each_entry_safe(struct accumulated_samples, samples, &state->timelines, link) {
        put_accumulated_sample(state, samples);
    }
    if (state->current_timeline_sample) {
        put_accumulated_sample(state, state->current_timeline_sample);
        state->current_timeline_sample = NULL;
    }
    _mesa_hash_table_clear(state->hw_contexts_table, NULL);

    state->n_timelines = 0;
    state->last_hw_id = GPUTOP_OA_INVALID_CTX_ID;

    list_for_each_entry_safe(struct accumulated_samples, samples,
                             &state->graphs, link) {
        put_accumulated_sample(state, samples);
    }
    if (state->current_graph_sample) {
        put_accumulated_sample(state, state->current_graph_sample);
        state->current_graph_sample = NULL;
    }
    state->n_graphs = 0;

    if (state->last_chunk) {
        put_i915_perf_chunk(state->last_chunk);
        state->last_chunk = NULL;
    }
    state->last_header = NULL;

    assert(list_empty(&state->i915_perf_chunks));
}

static void
delete_process_entry(struct hash_entry *entry)
{
    free(entry->data);
}

static void
clear_perf_tracepoints_data(struct connection_state *state)
{
    list_for_each_entry_safe(struct perf_tracepoint_data, data,
                             &state->perf_tracepoints_data, link) {
        list_del(&data->link);
        free(data);
    }
}

static void
clear_logs(struct connection_state *state)
{
    for (int i = 0; i < state->n_messages; i++)
        free(state->messages[i].msg);
    state->n_messages = 0;
}

static void
reset_connection_state(void)
{
    struct connection_state *state = &context.connection_state;

    /**/
    if (state->features) {
        gputop__message__free_unpacked(state->features, NULL);
        state->features = NULL;
    }
    if (state->tracepoint_info) {
        gputop__message__free_unpacked(state->tracepoint_info, NULL);
        state->tracepoint_info = NULL;
    }

    _mesa_hash_table_clear(state->metrics_map, NULL);

    list_inithead(&state->hw_contexts);

    list_inithead(&state->streams);
    state->selected_uuid = -1;

    /**/
    i915_perf_empty_samples(state);

    /**/
    clear_perf_tracepoints_data(state);

    _mesa_hash_table_clear(state->perf_tracepoints_name_table, NULL);
    _mesa_hash_table_clear(state->perf_tracepoints_uuid_table, NULL);
    list_for_each_entry_safe(struct perf_tracepoint, tp, &state->perf_tracepoints, link) {
        destroy_perf_tracepoint(state, tp);
    }

    /**/
    _mesa_hash_table_clear(state->processes_table, delete_process_entry);

    clear_logs(state);

    state->stream_id = 1; /* 0 reserved for closed/invalid */
}

/**/

static struct hw_context *
get_hw_context(struct connection_state *state, uint32_t hw_id)
{
    struct hash_entry *entry =
        _mesa_hash_table_search(state->hw_contexts_table, (void *)(uintptr_t)hw_id);

    struct hw_context *new_context;
    if (entry) {
        new_context = (struct hw_context *) entry->data;
        new_context->n_samples++;
        return new_context;
    }

    new_context = (struct hw_context *) calloc(1, sizeof(*new_context));
    snprintf(new_context->name, sizeof(new_context->name), "id: 0x%x", hw_id);
    new_context->hw_id = hw_id;
    new_context->timeline_row = _mesa_hash_table_num_entries(state->hw_contexts_table);
    new_context->n_samples = 1;

    _mesa_hash_table_insert(state->hw_contexts_table,
                            (void *)(uintptr_t)hw_id,
                            new_context);

    list_for_each_entry(struct hw_context, context, &state->hw_contexts, link) {
        if (context->hw_id > new_context->hw_id) {
            list_addtail(&new_context->link, &context->link);
            break;
        }
    }

    if (new_context->link.prev == new_context->link.next)
        list_addtail(&new_context->link, &state->hw_contexts);

    return new_context;
}

static void
put_hw_context(struct connection_state *state, struct hw_context *old_context)
{
    if (!old_context || --old_context->n_samples)
        return;

    struct hash_entry *entry =
        _mesa_hash_table_search(state->hw_contexts_table,
                                (void *)(uintptr_t)old_context->hw_id);
    _mesa_hash_table_remove(state->hw_contexts_table, entry);
    list_del(&old_context->link);
    free(old_context);

    uint32_t i = 0;
    list_for_each_entry(struct hw_context, context, &state->hw_contexts, link)
        context->timeline_row = i++;
}

static void
hw_context_add_time(struct hw_context *context,
                    struct accumulated_samples *samples, bool add)
{
    uint64_t delta = samples->timestamp_end - samples->timestamp_start;
    context->time_spent += add ? delta : -delta;
}

static struct accumulated_samples *
get_accumulated_sample(struct connection_state *state,
                       struct i915_perf_chunk *chunk,
                       const struct drm_i915_perf_record_header *header,
                       uint32_t hw_id)
{
    struct accumulated_samples *samples;

    if (list_empty(&state->free_samples)) {
        samples = (struct accumulated_samples *) calloc(1, sizeof(*samples));
    } else {
        samples = list_first_entry(&state->free_samples, struct accumulated_samples, link);
        list_del(&samples->link);
        memset(samples, 0, sizeof(*samples));
    }

    const uint8_t *report = (const uint8_t *)
        gputop_i915_perf_report_field(&i915_perf_config, header,
                                      GPUTOP_I915_PERF_FIELD_OA_REPORT);
    gputop_cc_oa_accumulator_init(&samples->accumulator,
                                  &state->devinfo,
                                  state->metric_set,
                                  false,
                                  state->oa_aggregation_period_ms * 1000000,
                                  report);

    list_inithead(&samples->link);
    samples->context = hw_id != 0 ? get_hw_context(state, hw_id) : NULL;
    samples->start_report.chunk = ref_i915_perf_chunk(chunk);
    samples->start_report.header = header;

    const uint64_t *cpu_timestamp = (const uint64_t *)
        gputop_i915_perf_report_field(&i915_perf_config, header,
                                      GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
    samples->timestamp_start = cpu_timestamp ?
        (*cpu_timestamp) : samples->accumulator.first_timestamp;

    return samples;
}

static void
put_accumulated_sample(struct connection_state *state,
                       struct accumulated_samples *samples)
{
    put_i915_perf_chunk(samples->start_report.chunk);
    put_i915_perf_chunk(samples->end_report.chunk);
    put_hw_context(state, samples->context);
    list_del(&samples->link);
    list_add(&samples->link, &state->free_samples);
}

static void
i915_perf_record_for_time(struct connection_state *state,
                          struct accumulated_samples *samples,
                          struct i915_perf_chunk *chunk,
                          const struct drm_i915_perf_record_header *header)
{
    samples->end_report.chunk = ref_i915_perf_chunk(chunk);
    samples->end_report.header = header;

    /* Put end timestamp */
    const uint64_t *cpu_timestamp = (const uint64_t *)
        gputop_i915_perf_report_field(&i915_perf_config, header,
                                      GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
    samples->timestamp_end =
        cpu_timestamp ? (*cpu_timestamp) : samples->accumulator.last_timestamp;

    /* Remove excess of samples */
    uint32_t max_graphs =
        (state->oa_visible_timeline_s * 1000.0f) / state->oa_aggregation_period_ms;
    while (state->n_graphs > max_graphs) {
        struct accumulated_samples *ex_samples =
            list_first_entry(&state->graphs, struct accumulated_samples, link);
        put_accumulated_sample(state, ex_samples);
        state->n_graphs--;
    }

    list_addtail(&samples->link, &state->graphs);
    state->n_graphs++;

    ImGui_ImplGtk3Cogl_ScheduleFrame();
}

static uint64_t query_cpu_clock(struct connection_state *state, uint64_t gpu_timestamp);

static void
i915_perf_record_for_hw_id(struct connection_state *state,
                           struct accumulated_samples *samples,
                           struct i915_perf_chunk *chunk,
                           const struct drm_i915_perf_record_header *header)
{
    samples->end_report.chunk = ref_i915_perf_chunk(chunk);
    samples->end_report.header = header;

    /* Put end timestamp */
    const uint64_t *cpu_timestamp = (const uint64_t *)
        gputop_i915_perf_report_field(&i915_perf_config, header,
                                      GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
    samples->timestamp_end =
        cpu_timestamp ? (*cpu_timestamp) : samples->accumulator.last_timestamp;

    /* Remove excess of samples */
    uint64_t aggregation_period_ns = state->oa_visible_timeline_s * 1000000000UL;
    struct accumulated_samples *first_samples =
        list_first_entry(&state->timelines, struct accumulated_samples, link);
    while (!list_empty(&state->timelines) &&
           (samples->timestamp_end - first_samples->timestamp_start) > aggregation_period_ns) {
        hw_context_add_time(first_samples->context, first_samples, false);
        put_accumulated_sample(state, first_samples);
        state->n_timelines--;
        first_samples = list_first_entry(&state->timelines, struct accumulated_samples, link);
    }

    list_addtail(&samples->link, &state->timelines);
    state->n_timelines++;

    hw_context_add_time(samples->context, samples, true);

    ImGui_ImplGtk3Cogl_ScheduleFrame();
}

static void
i915_perf_accumulate(struct connection_state *state,
                     struct i915_perf_chunk *chunk)
{
    struct i915_perf_chunk *last_chunk = state->last_chunk;
    const struct drm_i915_perf_record_header *header;
    const uint8_t *last = state->last_header ?
        ((const uint8_t *) gputop_i915_perf_report_field(&i915_perf_config,
                                                         state->last_header,
                                                         GPUTOP_I915_PERF_FIELD_OA_REPORT)) :
        NULL;

    for (header = (const struct drm_i915_perf_record_header *) chunk->data;
         (const uint8_t *) header < (chunk->data + chunk->length);
         header = (const struct drm_i915_perf_record_header *) (((const uint8_t *)header) + header->size))
    {
        switch (header->type) {
        case DRM_I915_PERF_RECORD_OA_BUFFER_LOST:
            g_warning("i915_oa: OA buffer error - all records lost");
            break;
        case DRM_I915_PERF_RECORD_OA_REPORT_LOST:
            g_warning("i915_oa: OA report lost");
            break;

        case DRM_I915_PERF_RECORD_SAMPLE: {
            const uint8_t *samples = (const uint8_t *)
                gputop_i915_perf_report_field(&i915_perf_config, header,
                                              GPUTOP_I915_PERF_FIELD_OA_REPORT);
            uint32_t hw_id = gputop_cc_oa_report_get_ctx_id(&state->devinfo, samples);

            if (!state->current_graph_sample)
                state->current_graph_sample = get_accumulated_sample(state, chunk, header, 0);
            if (last && state->last_hw_id != GPUTOP_OA_INVALID_CTX_ID &&
                !state->current_timeline_sample) {
                state->current_timeline_sample =
                    get_accumulated_sample(state, state->last_chunk, state->last_header,
                                           state->last_hw_id);
            }

            if (last) {
                struct gputop_cc_oa_accumulator *accumulator =
                    &state->current_graph_sample->accumulator;

                if (gputop_cc_oa_accumulate_reports(accumulator, last, samples)) {
                    uint64_t elapsed = (accumulator->last_timestamp -
                                        accumulator->first_timestamp);
                    uint32_t events = 0;

                    if (elapsed > (state->oa_aggregation_period_ms * 1000000ULL)) {
                        i915_perf_record_for_time(state, state->current_graph_sample,
                                                  chunk, header);
                        state->current_graph_sample =
                            get_accumulated_sample(state, chunk, header, 0);
                    }
                }

                if (state->current_timeline_sample) {
                    accumulator = &state->current_timeline_sample->accumulator;
                    if (gputop_cc_oa_accumulate_reports(accumulator, last, samples)) {
                        uint64_t elapsed =
                            accumulator->last_timestamp - accumulator->first_timestamp;

                        if (state->last_hw_id != hw_id ||
                            elapsed > (state->oa_aggregation_period_ms * 1000000ULL)) {
                            i915_perf_record_for_hw_id(state, state->current_timeline_sample,
                                                       chunk, header);
                            state->current_timeline_sample = NULL;
                        }
                    }
                }
            }

            last = samples;
            state->last_hw_id = hw_id;
            state->last_header = header;
            if (state->last_chunk) put_i915_perf_chunk(state->last_chunk);
            state->last_chunk = ref_i915_perf_chunk(chunk);
            break;
        }

        default:
            g_warning("i915 perf: Spurious header type = %d", header->type);
            return;
        }
    }
}

/**/

static const struct gputop_metric_set *
uuid_to_metric_set(const char *uuid)
{
    struct connection_state *state = &context.connection_state;
    struct hash_entry *entry =
        _mesa_hash_table_search(state->metrics_map, uuid);
    return entry ? ((struct gputop_metric_set *) entry->data) : NULL;
}

static const char *
uuid_to_name(const char *uuid)
{
    const struct gputop_metric_set *metric_set = uuid_to_metric_set(uuid);
    return metric_set ? metric_set->name : uuid;
}

static void
register_metric_set(const struct gputop_metric_set *metric_set, void *data)
{
    struct connection_state *state = &context.connection_state;

    _mesa_hash_table_insert(state->metrics_map,
                            metric_set->hw_config_guid, (void *) metric_set);
}

static void
register_platform_metrics(const Gputop__DevInfo *devinfo)
{
    static const struct {
        const char *devname;
        void (*add_metrics_cb)(const struct gputop_devinfo *devinfo,
                               void (*register_metric_set)(const struct gputop_metric_set *,
                                                           void *),
                               void *data);
    } devname_to_metric_func[] = {
        { "hsw", gputop_oa_add_metrics_hsw },
        { "bdw", gputop_oa_add_metrics_bdw },
        { "chv", gputop_oa_add_metrics_chv },
        { "sklgt2", gputop_oa_add_metrics_sklgt2 },
        { "sklgt3", gputop_oa_add_metrics_sklgt3 },
        { "sklgt4", gputop_oa_add_metrics_sklgt4 },
        { "kblgt2", gputop_oa_add_metrics_kblgt2 },
        { "kblgt3", gputop_oa_add_metrics_kblgt3 },
        { "bxt", gputop_oa_add_metrics_bxt },
        { "glk", gputop_oa_add_metrics_glk },
        { "cflgt2", gputop_oa_add_metrics_cflgt2 },
        { "cflgt3", gputop_oa_add_metrics_cflgt3 },
        { "cnl", gputop_oa_add_metrics_cnl },
    };
    struct connection_state *state = &context.connection_state;

    state->devinfo.timestamp_frequency = devinfo->timestamp_frequency;
    state->devinfo.devid = devinfo->devid;
    state->devinfo.gen = devinfo->gen;
    state->devinfo.n_eus = devinfo->n_eus;
    state->devinfo.n_eu_slices = devinfo->n_eu_slices;
    state->devinfo.n_eu_sub_slices = devinfo->n_eu_sub_slices;
    state->devinfo.eu_threads_count = devinfo->eu_threads_count;
    state->devinfo.subslice_mask = devinfo->subslice_mask;
    state->devinfo.slice_mask = devinfo->slice_mask;

    _mesa_hash_table_clear(state->metrics_map, NULL);
    for (uint32_t i = 0; i < ARRAY_SIZE(devname_to_metric_func); i++) {
        if (!strcmp(devinfo->devname, devname_to_metric_func[i].devname)) {
            devname_to_metric_func[i].add_metrics_cb(&state->devinfo,
                                                     register_metric_set, NULL);
            return;
        }
    }
}

extern "C" void
gputop_cr_console_log(const char *format, ...)
{
    va_list ap;
    char *str = NULL;

    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}

/**/

static uint64_t
oa_exponent_to_period_ns(struct connection_state *state, uint32_t exponent)
{
    return ((1UL << exponent) * 1000000000) / state->devinfo.timestamp_frequency;
}

static uint32_t
period_to_oa_exponent(struct connection_state *state, uint32_t period_ms)
{
    uint32_t i = 0;
    uint64_t prev_period_ns = oa_exponent_to_period_ns(state, 0),
        next_period_ns = oa_exponent_to_period_ns(state, 1),
        period_ns = period_ms * 1000000;

    while (i < 31 &&
           period_ns > next_period_ns) {
        i++;
        prev_period_ns = next_period_ns;
        next_period_ns = oa_exponent_to_period_ns(state, i + 1);
    }

    return i;
}

static void
close_i915_perf_stream(struct connection_state *state)
{
    if (is_stream_opened(&state->oa_stream))
        close_stream(&state->oa_stream);
}

static void
maybe_close_i915_perf_stream(struct connection_state *state)
{
    if (list_length(&context.i915_perf_windows) &&
        !context.timeline_window.base.opened)
        close_i915_perf_stream(state);
}

static void
open_i915_perf_stream(struct connection_state *state)
{
    if (!state->metric_set) return;

    assert(!is_stream_opened(&state->oa_stream));

    i915_perf_empty_samples(state);

    Gputop__OAStreamInfo oa_stream = GPUTOP__OASTREAM_INFO__INIT;
    oa_stream.uuid = (char *) state->metric_set->hw_config_guid;
    oa_stream.period_exponent =
        period_to_oa_exponent(state, state->oa_aggregation_period_ms);
    oa_stream.per_ctx_mode = false;
    oa_stream.cpu_timestamps = i915_perf_config.cpu_timestamps;
    oa_stream.gpu_timestamps = i915_perf_config.gpu_timestamps;

    Gputop__OpenStream stream = GPUTOP__OPEN_STREAM__INIT;
    stream.overwrite = false;
    stream.live_updates = true;
    stream.type_case = GPUTOP__OPEN_STREAM__TYPE_OA_STREAM;
    stream.oa_stream = &oa_stream;

    open_stream(&state->oa_stream, state, &stream);
}

/**/

static void
open_perf_events_streams(struct connection_state *state)
{
    // clear_perf_tracepoints_data(state);
    // list_for_each_entry(struct perf_event, tp, &state->perf_events, link)
    //     open_perf_event(state, tp);
}

static void
close_perf_events_streams(struct connection_state *state)
{
    // list_for_each_entry(struct perf_event, tp, &state->perf_events, link)
    //     close_perf_event(state, tp);
}

/**/

static void
open_perf_tracepoints_streams(struct connection_state *state)
{
    clear_perf_tracepoints_data(state);
    list_for_each_entry(struct perf_tracepoint, tp, &state->perf_tracepoints, link)
        open_perf_tracepoint(state, tp);
}

static void
close_perf_tracepoints_streams(struct connection_state *state)
{
    list_for_each_entry(struct perf_tracepoint, tp, &state->perf_tracepoints, link)
        close_perf_tracepoint(state, tp);
}

/**/

static void
request_features(void)
{
    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_GET_FEATURES;
    request.get_features = true;

    send_pb_message(&request.base);
}

/**/

static void
update_cpu_colors(int n_cpus)
{
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        float r, g, b;
        ImGui::ColorConvertHSVtoRGB(cpu * 1.0f / n_cpus, 1.0f, 1.0f, r, g, b);
        context.cpu_colors[cpu] = ImColor(r, g, b);
    }
}

static bool
add_cpu_stats(Gputop__Message *message)
{
    struct connection_state *state = &context.connection_state;
    if (!is_stream_opened(&state->cpu_stats_stream) ||
        message->cpu_stats->id != state->cpu_stats_stream.id)
        return false;

    uint32_t max_cpu_stats =
        (state->cpu_stats_visible_timeline_s * 1000.0f) / state->cpu_stats_sampling_period_ms;
    struct cpu_stat *stat;

    /* Remove excess of samples */
    while (state->n_cpu_stats > max_cpu_stats) {
        stat = list_first_entry(&state->cpu_stats, struct cpu_stat, link);
        list_del(&stat->link);
        gputop__message__free_unpacked(stat->stat, NULL);
        free(stat);
        state->n_cpu_stats--;
    }

    if (state->n_cpu_stats < max_cpu_stats) {
        stat = (struct cpu_stat *) calloc(1, sizeof(*stat));
        state->n_cpu_stats++;
    } else {
        stat = list_first_entry(&state->cpu_stats, struct cpu_stat, link);
        list_del(&stat->link);
        gputop__message__free_unpacked(stat->stat, NULL);
    }

    stat->stat = message;
    list_addtail(&stat->link, &state->cpu_stats);

    ImGui_ImplGtk3Cogl_ScheduleFrame();

    return true;
}

static void
open_cpu_stats_stream(int sampling_period_ms)
{
    struct connection_state *state = &context.connection_state;

    state->cpu_stats_sampling_period_ms = sampling_period_ms;

    /**/
    list_for_each_entry_safe(struct cpu_stat, stat, &state->cpu_stats, link) {
        list_del(&stat->link);
        gputop__message__free_unpacked(stat->stat, NULL);
        free(stat);
    }
    state->n_cpu_stats = 0;

    Gputop__CpuStatsInfo cpu_stats = GPUTOP__CPU_STATS_INFO__INIT;
    cpu_stats.sample_period_ms = sampling_period_ms;

    Gputop__OpenStream stream = GPUTOP__OPEN_STREAM__INIT;
    stream.overwrite = false;
    stream.live_updates = true;
    stream.type_case = GPUTOP__OPEN_STREAM__TYPE_CPU_STATS;
    stream.cpu_stats = &cpu_stats;

    open_stream(&state->cpu_stats_stream, state, &stream);
}

static void
reopen_cpu_stats_stream(int sampling_period_ms)
{
    struct connection_state *state = &context.connection_state;

    if (is_stream_opened(&state->cpu_stats_stream))
        close_stream(&state->cpu_stats_stream);
    open_cpu_stats_stream(sampling_period_ms);
}

/**/

static void
handle_perf_data(uint32_t stream_id, const uint8_t *data, size_t len)
{
    struct connection_state *state = &context.connection_state;
    struct hash_entry *entry =
        _mesa_hash_table_search(state->perf_tracepoints_stream_table,
                                (void *)(uintptr_t)stream_id);
    if (!entry) {
        fprintf(stderr, "Unknown stream id=%u\n", stream_id);
        return;
    }

    struct perf_tracepoint_stream *stream = (struct perf_tracepoint_stream *) entry->data;
    const uint8_t *data_end = data + len;

    while (data < data_end) {
        const struct perf_data_tracepoint *point =
            (const struct perf_data_tracepoint *) data;
        add_tracepoint_stream_data(stream, data, point->header.size);
        data += point->header.size;
    }
}

static void
handle_i915_perf_data(uint32_t stream_id, const uint8_t *data, size_t len)
{
    struct connection_state *state = &context.connection_state;

    if (stream_id == state->oa_stream.id) {
        struct i915_perf_chunk *chunk = get_i915_perf_chunk(state, data, len);
        i915_perf_accumulate(state, chunk);
        put_i915_perf_chunk(chunk);
    } else
        fprintf(stderr, "discard wrong oa stream id=%i/%i\n",
                stream_id, state->oa_stream.id);
}

static void
log_add(int level, const char *msg)
{
    struct connection_state *state = &context.connection_state;

    if (state->n_messages < ARRAY_SIZE(state->messages)) {
        state->messages[state->n_messages].level = level;
        state->messages[state->n_messages].msg = strdup(msg);
        state->n_messages++;
    } else {
        int idx = (++state->start_message + state->n_messages) % ARRAY_SIZE(state->messages);

        free(state->messages[idx].msg);

        state->messages[idx].level = level;
        state->messages[idx].msg = strdup(msg);
    }
}

static void
handle_protobuf_message(const uint8_t *data, size_t len)
{
    Gputop__Message *message =
        (Gputop__Message *) protobuf_c_message_unpack(&gputop__message__descriptor,
                                                      NULL, /* default allocator */
                                                      len, data);

    if (!message) {
        fprintf(stderr, "Failed to unpack message len=%u", len);
        return;
    }

    struct connection_state *state = &context.connection_state;
    switch (message->cmd_case) {
    case GPUTOP__MESSAGE__CMD_ERROR:
        log_add(0, message->error);
        break;
    case GPUTOP__MESSAGE__CMD_ACK:
        //fprintf(stderr, "ack\n");
        break;
    case GPUTOP__MESSAGE__CMD_FEATURES:
        context.connection_state.features = message;
        update_cpu_colors(message->features->n_cpus);
        register_platform_metrics(message->features->devinfo);
        message = NULL; /* Save that structure for internal use */
        break;
    case GPUTOP__MESSAGE__CMD_LOG:
        for (size_t i = 0; i < message->log->n_entries; i++) {
            log_add(message->log->entries[i]->log_level,
                    message->log->entries[i]->log_message);
        }
        break;
    case GPUTOP__MESSAGE__CMD_CLOSE_NOTIFY: {
        struct stream *stream = find_stream(state, message->close_notify->id);
        if (stream)
            fprintf(stderr, "unexpected close notify id=%i\n",
                    message->close_notify->id);
        break;
    }
    case GPUTOP__MESSAGE__CMD_FILL_NOTIFY: {
        struct stream *stream = find_stream(state, message->fill_notify->stream_id);
        if (stream)
            stream->fill = message->fill_notify->fill_percentage;
        break;
    }
    case GPUTOP__MESSAGE__CMD_PROCESS_INFO: {
        struct hash_entry *entry =
            _mesa_hash_table_search(state->processes_table,
                                    (void *)(uintptr_t)message->process_info->pid);
        if (entry) {
            struct process_info *info = (struct process_info *) entry->data;
            snprintf(info->cmd, sizeof(info->cmd), "%s", message->process_info->comm);
            snprintf(info->cmd_line, sizeof(info->cmd_line), "%s", message->process_info->cmd_line);

            update_hw_contexts_process_info(state, info);
        }
        break;
    }
    case GPUTOP__MESSAGE__CMD_CPU_STATS:
        if (add_cpu_stats(message))
            message = NULL;
        break;
    case GPUTOP__MESSAGE__CMD_TRACEPOINT_INFO: {
        if (state->tracepoint_info)
            gputop__message__free_unpacked(state->tracepoint_info, NULL);
        state->tracepoint_info = message;

        struct hash_entry *entry =
            _mesa_hash_table_search(state->perf_tracepoints_uuid_table, message->reply_uuid);
        if (entry) {
            update_tracepoint((struct perf_tracepoint *) entry->data,
                              message->tracepoint_info);
        }
        message = NULL;
        break;
    }
    case GPUTOP__MESSAGE__CMD__NOT_SET:
        assert(0);
    }

    if (message)
        gputop__message__free_unpacked(message, NULL);
}

static void
on_connection_data(gputop_connection_t *conn,
                   const void *payload, size_t payload_len,
                   void *user_data)
{
    const uint8_t *msg_type = (const uint8_t *) payload;
    const uint8_t *data = (const uint8_t *) payload + 8;
    size_t len = payload_len - 8;

    switch (*msg_type) {
    case 1: {
        const uint32_t *stream_id =
            (const uint32_t *) ((const uint8_t *) payload + 4);
        handle_perf_data(*stream_id, data, len);
        break;
    }
    case 2:
        handle_protobuf_message(data, len);
        break;
    case 3: {
        const uint32_t *stream_id =
            (const uint32_t *) ((const uint8_t *) payload + 4);
        handle_i915_perf_data(*stream_id, data, len);
        break;
    }
    default:
        fprintf(stderr, "unknown msg type=%hhi", *msg_type);
        break;
    }
}

static void
on_connection_closed(gputop_connection_t *conn,
                     const char *error,
                     void *user_data)
{
    struct connection_state *state = &context.connection_state;
    free(state->connection_error);
    state->connection_error = NULL;
    if (error)
        state->connection_error = strdup(error);
    else
        state->connection_error = strdup("Disconnected");
    context.connection_state.connection = NULL;
}

static void
on_connection_ready(gputop_connection_t *conn,
                    void *user_data)
{
    struct connection_state *state = &context.connection_state;

    reset_connection_state();
    request_features();
    open_cpu_stats_stream(state->cpu_stats_sampling_period_ms);
    // open_clock_stream(state->clock_sampling_period_ms);
}

static void
reconnect(void)
{
    struct connection_state *state = &context.connection_state;
    if (state->connection)
        gputop_connection_close(state->connection);
    free(state->connection_error);
    state->connection_error = NULL;
    state->connection = gputop_connect(state->host_address, state->host_port,
                                       on_connection_ready,
                                       on_connection_data,
                                       on_connection_closed, NULL);
}

/**/

static void
stop_sampling(struct connection_state *state)
{
    if (!state->is_sampling)
        return;

    close_i915_perf_stream(state);
    close_perf_events_streams(state);
    close_perf_tracepoints_streams(state);

    state->is_sampling = false;
}

static void
start_sampling(struct connection_state *state)
{
    if (state->is_sampling)
        stop_sampling(state);

    _mesa_hash_table_clear(state->processes_table, delete_process_entry);

    open_i915_perf_stream(state);
    open_perf_events_streams(state);
    open_perf_tracepoints_streams(state);

    state->is_sampling = true;
}

/**/

static void
pretty_print_value(gputop_counter_units_t unit,
                   double value, char *buffer, size_t length)
{
    static const char *times[] = { "ns", "us", "ms", "s" };
    static const char *bytes[] = { "B", "KiB", "MiB", "GiB" };
    static const char *freqs[] = { "Hz", "KHz", "MHz", "GHz" };
    static const char *texels[] = { "texels", "K texels", "M texels", "G texels" };
    static const char *pixels[] = { "pixels", "K pixels", "M pixels", "G pixels" };
    static const char *cycles[] = { "cycles", "K cycles", "M cycles", "G cycles" };
    static const char *threads[] = { "threads", "K threads", "M threads", "G threads" };
    const char **scales = NULL;

    switch (unit) {
    case GPUTOP_PERFQUERY_COUNTER_UNITS_BYTES:   scales = bytes; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_HZ:      scales = freqs; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_NS:
    case GPUTOP_PERFQUERY_COUNTER_UNITS_US:      scales = times; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_PIXELS:  scales = pixels; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_TEXELS:  scales = texels; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_THREADS: scales = threads; break;
    }

    if (scales) {
        const double base = unit == GPUTOP_PERFQUERY_COUNTER_UNITS_BYTES ? 1024 : 1000;
        const double multipliers[4] = { 0, base, base * base, base * base * base };

        if (unit == GPUTOP_PERFQUERY_COUNTER_UNITS_US)
            value *= 1000;

        int i = 0;
        while (value >= base && i < 3) {
            value /= base;
            i++;
        }
        snprintf(buffer, length, "%.3f %s", value, scales ? scales[i] : "");
    } else {
        if (unit == GPUTOP_PERFQUERY_COUNTER_UNITS_PERCENT)
            snprintf(buffer, length, "%.2f %%", value);
        else
            snprintf(buffer, length, "%f", value);
    }
}

static void
pretty_print_counter_value(const struct gputop_metric_set_counter *counter,
                           double value, char *buffer, size_t length)
{
    pretty_print_value(counter->units, value, buffer, length);
}

static double
read_counter_max(struct connection_state *state,
                 struct accumulated_samples *sample,
                 const struct gputop_metric_set_counter *counter)
{
    double value;

    switch (counter->data_type) {
    case GPUTOP_PERFQUERY_COUNTER_DATA_UINT64:
    case GPUTOP_PERFQUERY_COUNTER_DATA_UINT32:
    case GPUTOP_PERFQUERY_COUNTER_DATA_BOOL32:
        if (counter->max_uint64)
            return counter->max_uint64(&state->devinfo,
                                       state->metric_set,
                                       sample->accumulator.deltas);
        break;
    case GPUTOP_PERFQUERY_COUNTER_DATA_DOUBLE:
    case GPUTOP_PERFQUERY_COUNTER_DATA_FLOAT:
        if (counter->max_float)
            return counter->max_float(&state->devinfo,
                                      state->metric_set,
                                      sample->accumulator.deltas);
        break;
    }

    return FLT_MAX;
}

static double
get_counter_max(struct connection_state *state,
                struct i915_perf_window_counter *counter)
{
    struct accumulated_samples *last_sample =
        list_last_entry(&state->graphs,
                        struct accumulated_samples, link);
    counter->latest_max = MAX2(read_counter_max(state, last_sample,
                                                counter->counter),
                               counter->latest_max);
    return counter->latest_max;
}

static double
read_counter_value(struct connection_state *state,
                   struct accumulated_samples *sample,
                   const struct gputop_metric_set_counter *counter)
{
    switch (counter->data_type) {
    case GPUTOP_PERFQUERY_COUNTER_DATA_UINT64:
    case GPUTOP_PERFQUERY_COUNTER_DATA_UINT32:
    case GPUTOP_PERFQUERY_COUNTER_DATA_BOOL32:
        return counter->oa_counter_read_uint64(&state->devinfo,
                                               state->metric_set,
                                               sample->accumulator.deltas);
        break;
    case GPUTOP_PERFQUERY_COUNTER_DATA_DOUBLE:
    case GPUTOP_PERFQUERY_COUNTER_DATA_FLOAT:
        return counter->oa_counter_read_float(&state->devinfo,
                                              state->metric_set,
                                              sample->accumulator.deltas);
        break;
    }

    return 0.0f;
}

static float *
get_counter_samples(struct connection_state *state,
                    int max_graphs,
                    struct i915_perf_window_counter *counter)
{
    float *values = ensure_plot_accumulator(max_graphs);
    int i;

    for (i = 0; i < (max_graphs - state->n_graphs); i++)
        values[i] = 0.0f;

    struct accumulated_samples *sample =
        list_first_entry(&state->graphs,
                         struct accumulated_samples, link);
    for (; i < max_graphs; i++) {
        values[i] = read_counter_value(state, sample, counter->counter);
        sample = list_first_entry(&sample->link,
                                  struct accumulated_samples, link);
    }

    return values;
}

static void
add_counter_i915_perf_window(struct i915_perf_window *window,
                             const struct gputop_metric_set_counter *counter)
{
    struct i915_perf_window_counter *c =
        (struct i915_perf_window_counter *) calloc(1, sizeof(*c));

    c->counter = counter;
    list_addtail(&c->link, &window->counters);
}

static void
remove_counter_i915_perf_window(struct i915_perf_window_counter *counter)
{
    list_del(&counter->link);
    free(counter);
}

static bool
select_i915_perf_counter(struct connection_state *state,
                         const struct gputop_metric_set_counter **out_counter)
{
    bool selected = false;
    static ImGuiTextFilter filter;
    filter.Draw();

    if (!state->metric_set) return false;

    struct accumulated_samples *last_sample =
        list_last_entry(&state->graphs,
                        struct accumulated_samples, link);

    ImGui::BeginChild("##block", ImVec2(0, 300));
    for (int c = 0; c < state->metric_set->n_counters; c++) {
        bool hovered;
        const struct gputop_metric_set_counter *counter =
            &state->metric_set->counters[c];
        if (!filter.PassFilter(counter->name)) continue;
        if (ImGui::Selectable(counter->name)) {
            *out_counter = counter;
            selected = true;
        }
        hovered = ImGui::IsItemHovered();
        double value = read_counter_value(state, last_sample, counter);
        ImGui::ProgressBar(value / read_counter_max(state, last_sample, counter),
                           ImVec2(100, 0)); ImGui::SameLine();
        char svalue[100];
        pretty_print_counter_value(counter, value, svalue, sizeof(svalue));
        if (ImGui::Selectable(svalue, hovered)) {
            *out_counter = counter;
            selected = true;
        }
    }
    ImGui::EndChild();

    return selected;
}

static void
display_i915_perf_window(struct window *win)
{
    struct i915_perf_window *window = (struct i915_perf_window *) win;
    struct connection_state *state = &context.connection_state;
    uint32_t max_graphs =
        (state->oa_visible_timeline_s * 1000.0f) / state->oa_aggregation_period_ms;

    bool open_popup = ImGui::Button("Add counter");
    if (open_popup)
        ImGui::OpenPopup("counter picker");
    if (ImGui::BeginPopup("counter picker")) {
        const struct gputop_metric_set_counter *counter = NULL;
        if (select_i915_perf_counter(state, &counter))
            add_counter_i915_perf_window(window, counter);
        ImGui::EndPopup();
    }
    if (state->n_graphs < max_graphs) {
        ImGui::SameLine(); ImGui::Text("Loading:"); ImGui::SameLine();
        ImGui::ProgressBar((float) state->n_graphs / max_graphs);
    }
    ImGui::Text("n_timelines=%u / n_graphs=%u", state->n_timelines, state->n_graphs);

    ImGui::BeginChild("##block");
    ImGui::PushStyleColor(ImGuiCol_PlotLines, Gputop::GetColor(GputopCol_OaGraph));
    list_for_each_entry_safe(struct i915_perf_window_counter, c, &window->counters, link) {
        ImGui::PushID(c);
        if (ImGui::Button("X")) { remove_counter_i915_perf_window(c); }
        ImGui::PopID();
        if (ImGui::IsItemHovered()) { ImGui::SetTooltip("Remove counter"); } ImGui::SameLine();
        const float *values = get_counter_samples(state, max_graphs, c);
        ImGui::PlotLines("", values, max_graphs, 0,
                         c->counter->name, 0, get_counter_max(state, c),
                         ImVec2(ImGui::GetContentRegionAvailWidth() - 10, 50.0f));
        if (ImGui::IsItemHovered()) {
            float item_width = ImGui::GetItemRectSize().x;
            float item_pos = ImGui::GetMousePos().x - ImGui::GetItemRectMin().x;
            char tooltip_tex[100];
            pretty_print_counter_value(c->counter,
                                       values[(int)(state->n_graphs * item_pos / item_width)],
                                       tooltip_tex, sizeof(tooltip_tex));
            ImGui::SetTooltip("%s", tooltip_tex);
        }
    }
    ImGui::PopStyleColor();
    ImGui::EndChild();
}

static void
cleanup_counters_i915_perf_window(struct i915_perf_window *window)
{
    list_for_each_entry_safe(struct i915_perf_window_counter, c,
                             &window->counters, link) {
        list_del(&c->link);
        free(c);
    }
}

static void
destroy_i915_perf_window(struct window *win)
{
    struct i915_perf_window *window = (struct i915_perf_window *) win;

    cleanup_counters_i915_perf_window(window);
    list_del(&window->link);
    free(window);

    maybe_close_i915_perf_stream(&context.connection_state);
}

static void
reset_i915_perf_window(struct window *win)
{
    struct i915_perf_window *window = (struct i915_perf_window *) win;
    cleanup_counters_i915_perf_window(window);
}

static void
new_i915_perf_window(void)
{
    struct i915_perf_window *window =
        (struct i915_perf_window *) calloc(1, sizeof(*window));

    snprintf(window->base.name, sizeof(window->base.name),
             "i915 OA counters##%p", window);
    window->base.size = ImVec2(400, 200);
    window->base.display = display_i915_perf_window;
    window->base.destroy = destroy_i915_perf_window;
    window->base.reset = reset_i915_perf_window;
    window->base.opened = true;

    list_inithead(&window->counters);

    list_add(&window->base.link, &context.windows);
    list_add(&window->link, &context.i915_perf_windows);
}

/**/

static void
display_accumulated_reports(struct connection_state *state,
                            struct accumulated_samples *samples)
{
    struct i915_perf_chunk *chunk = samples->start_report.chunk;
    const struct drm_i915_perf_record_header *header = (const struct drm_i915_perf_record_header *) samples->start_report.header;
    do {
        while ((const uint8_t *) header < (chunk->data + chunk->length)) {
            switch (header->type) {
            case DRM_I915_PERF_RECORD_OA_BUFFER_LOST:
                ImGui::Text("OA buffer lost");
                break;
            case DRM_I915_PERF_RECORD_OA_REPORT_LOST:
                ImGui::Text("OA report lost");
                break;

            case DRM_I915_PERF_RECORD_SAMPLE: {
                const uint64_t *cpu_timestamp = (const uint64_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
                const uint64_t *gpu_timestamp = (const uint64_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_GPU_TIMESTAMP);
                const uint8_t *report = (const uint8_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_OA_REPORT);

                if (ImGui::TreeNode(report, "rcs=%08x(%lx scaled) rcs64=%016lx cpu=%lx",
                                    gputop_cc_oa_report_get_timestamp(report),
                                    gputop_timebase_scale_ns(&state->devinfo,
                                                             gputop_cc_oa_report_get_timestamp(report)),
                                    gpu_timestamp ? *gpu_timestamp : 0ULL,
                                    cpu_timestamp ? *cpu_timestamp : 0ULL)) {
                    /* Display report fields */
                    ImGui::Text("id=0x%x reason=%s",
                                gputop_cc_oa_report_get_ctx_id(&state->devinfo, report),
                                gputop_cc_oa_report_get_reason(&state->devinfo, report));
                    ImGui::TreePop();
                }
                break;
            }

            default:
                g_warning("i915 perf: Spurious header type = %d", header->type);
                break;
            }

            if (header == samples->end_report.header)
                break;

            header = (const struct drm_i915_perf_record_header *) (((const uint8_t *)header) + header->size);
        }

        if (samples->end_report.chunk &&
            samples->start_report.chunk != samples->end_report.chunk) {
            chunk = list_first_entry(&chunk->link, struct i915_perf_chunk, link);
            header = (const struct drm_i915_perf_record_header *) chunk->data;
        } else
            chunk = samples->end_report.chunk;
    } while (chunk != samples->end_report.chunk);
}

static void
display_report_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    ImGui::Columns(3);
    if (state->last_header) {
        const uint32_t *last_report = (const uint32_t *)
            gputop_i915_perf_report_field(&i915_perf_config, state->last_header,
                                          GPUTOP_I915_PERF_FIELD_OA_REPORT);
        for (uint32_t i = 0; i < 64; i++)
            ImGui::Text("%u\t: 0x%08x", i, last_report[i]);
    }

    // ImGui::NextColumn();
    // if (state->n_timelines > 0) {
    //     struct accumulated_samples *first =
    //         list_first_entry(&state->timelines, struct accumulated_samples, link);
    //     struct accumulated_samples *last =
    //         list_last_entry(&state->timelines, struct accumulated_samples, link);
    //     uint64_t total_time = last->timestamp_start - first->timestamp_end;

    //     list_for_each_entry_safe(struct hw_context, context,
    //                              &state->hw_contexts, link) {
    //         ImGui::Text("hw_id %lx : %.2f", context->hw_id,
    //                     100.0f * ((double)context->time_spent / total_time));
    //     }
    // }

    // ImGui::NextColumn();
    // list_for_each_entry(struct perf_tracepoint_data, tp_data, &state->perf_tracepoints_data, link) {
    //     ImGui::Text("%s cputs=%lx", tp_data->tp->name, tp_data->data.time);
    // }

    struct {
        uint64_t start;
        uint64_t end;
    } hovered_window = { 0ULL, 0ULL };

    ImGui::NextColumn();
    list_for_each_entry(struct accumulated_samples, samples, &state->timelines, link) {
        const uint64_t *cpu_ts0 = (const uint64_t *)
            gputop_i915_perf_report_field(&i915_perf_config,
                                          samples->start_report.header,
                                          GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
        const uint64_t *cpu_ts1 = (const uint64_t *)
            gputop_i915_perf_report_field(&i915_perf_config,
                                          samples->end_report.header,
                                          GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
        char cpu_time_length[20];
        pretty_print_value(GPUTOP_PERFQUERY_COUNTER_UNITS_NS,
                           cpu_ts0 ? (*cpu_ts1 - *cpu_ts0) : 0UL,
                           cpu_time_length, sizeof(cpu_time_length));
        char gpu_time_length[20];
        pretty_print_value(GPUTOP_PERFQUERY_COUNTER_UNITS_NS,
                           samples->accumulator.last_timestamp -
                           samples->accumulator.first_timestamp,
                           gpu_time_length, sizeof(gpu_time_length));
        const uint8_t *report0 = (const uint8_t *)
            gputop_i915_perf_report_field(&i915_perf_config,
                                          samples->start_report.header,
                                          GPUTOP_I915_PERF_FIELD_OA_REPORT);
        const uint8_t *report1 = (const uint8_t *)
            gputop_i915_perf_report_field(&i915_perf_config,
                                          samples->end_report.header,
                                          GPUTOP_I915_PERF_FIELD_OA_REPORT);

        if (ImGui::TreeNode(samples, "%s rcs=%lx-%lx ts=%lx-%lx(%lx) time=%s/%s",
                            samples->context->name,
                            gputop_cc_oa_report_get_timestamp(report0),
                            gputop_cc_oa_report_get_timestamp(report1),
                            samples->timestamp_start, samples->timestamp_end,
                            gputop_timebase_scale_ns(&state->devinfo,
                                                     gputop_cc_oa_report_get_timestamp(report1) -
                                                     gputop_cc_oa_report_get_timestamp(report0)),
                            cpu_time_length, gpu_time_length)) {
            display_accumulated_reports(state, samples);
            ImGui::TreePop();
        }
        if (ImGui::IsItemHovered() && cpu_ts0) hovered_window = { *cpu_ts0, *cpu_ts1 };
    }

    ImGui::NextColumn();
    list_for_each_entry(struct i915_perf_chunk, chunk, &state->i915_perf_chunks, link) {
        for (const struct drm_i915_perf_record_header *header = (const struct drm_i915_perf_record_header *) chunk->data;
             (const uint8_t *) header < (chunk->data + chunk->length);
             header = (const struct drm_i915_perf_record_header *) (((const uint8_t *)header) + header->size)) {
            switch (header->type) {
            case DRM_I915_PERF_RECORD_OA_BUFFER_LOST:
                ImGui::Text("OA buffer lost");
                break;
            case DRM_I915_PERF_RECORD_OA_REPORT_LOST:
                ImGui::Text("OA report lost");
                break;

            case DRM_I915_PERF_RECORD_SAMPLE: {
                const uint64_t *cpu_timestamp = (const uint64_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_CPU_TIMESTAMP);
                const uint64_t *gpu_timestamp = (const uint64_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_GPU_TIMESTAMP);
                const uint8_t *report = (const uint8_t *)
                    gputop_i915_perf_report_field(&i915_perf_config, header,
                                                  GPUTOP_I915_PERF_FIELD_OA_REPORT);
                bool hovered = cpu_timestamp &&
                  (*cpu_timestamp >= hovered_window.start && *cpu_timestamp <= hovered_window.end);

                if (ImGui::TreeNodeEx(report,
                                      hovered ? (ImGuiTreeNodeFlags_Selected | ImGuiTreeNodeFlags_DefaultOpen) : 0,
                                      "rcs=%08x rcs64=%016lx cpu=%lx",
                                      gputop_cc_oa_report_get_timestamp(report),
                                      gpu_timestamp ? *gpu_timestamp : 0ULL,
                                      cpu_timestamp ? *cpu_timestamp : 0ULL)) {
                    /* Display report fields */
                    ImGui::Text("id=0x%x reason=%s",
                                gputop_cc_oa_report_get_ctx_id(&state->devinfo, report),
                                gputop_cc_oa_report_get_reason(&state->devinfo, report));
                    ImGui::TreePop();
                }
                break;
            }

            default:
                ImGui::Text("i915 perf: Spurious header type = %d", header->type);
                break;
            }
        }
    }
}

static void
show_report_window(void)
{
    struct window *window = &context.report_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name),
             "Last perf report##%p", window);
    window->size = ImVec2(400, 400);
    window->display = display_report_window;
    window->destroy = hide_window;
    window->opened = true;

    list_add(&window->link, &context.windows);
}

/**/

static void
get_timeline_bounds(struct timeline_window *window,
                    struct connection_state *state,
                    uint64_t *start, uint64_t *end)
{
    const uint64_t max_length = state->oa_visible_timeline_s * 1000000000ULL;

    struct accumulated_samples *oa_end = list_empty(&state->timelines) ?
        NULL : list_last_entry(&state->timelines, struct accumulated_samples, link);
    struct perf_tracepoint_data *tp_end = list_empty(&state->perf_tracepoints_data) ?
        NULL : list_last_entry(&state->perf_tracepoints_data, struct perf_tracepoint_data, link);

    uint64_t merged_end_ts = MAX2(oa_end ? oa_end->timestamp_end : 0,
                                  tp_end ? tp_end->data.time : 0);

    uint64_t start_ts = merged_end_ts - max_length + window->zoom_start;
    uint64_t end_ts = window->zoom_length == 0 ?
        merged_end_ts : start_ts + window->zoom_length;

    *start = start_ts;
    *end = end_ts;
}

static void
display_i915_perf_timeline_window(struct timeline_window *window,
                                  struct connection_state *state)
{
    const uint64_t max_length = state->oa_visible_timeline_s * 1000000000ULL;

    if (ImGui::Button("Reset zoom##i915")) {
        window->zoom_start = 0;
        window->zoom_length = max_length;
    } ImGui::SameLine();
    if (ImGui::Button("Zoom out##i915")) {
        uint64_t half_zoom = window->zoom_length / 2;
        window->zoom_start = window->zoom_start < half_zoom ? 0ULL :
            (window->zoom_start - half_zoom);
        window->zoom_length = MIN2(2 * window->zoom_length, max_length);
    } ImGui::SameLine();
    if (ImGui::Button("Zoom in##i915")) {
        window->zoom_start += window->zoom_length / 4;
        window->zoom_length /= 2;
    } ImGui::SameLine();
    {
        char time[20];
        pretty_print_value(GPUTOP_PERFQUERY_COUNTER_UNITS_NS,
                           window->zoom_length == 0 ? max_length : window->zoom_length,
                           time, sizeof(time));
        ImGui::Text("time interval : %s", time);
    } ImGui::SameLine();
    if (ImGui::Button("Show reports")) {
        if (!window->reports_window.opened) {
            window->reports_window.opened = true;
            list_add(&window->reports_window.link, &context.windows);
        }
    }

    uint64_t start_ts, end_ts;
    get_timeline_bounds(window, state, &start_ts, &end_ts);

    ImVec2 new_zoom;
    static const char *units[] = { "ns", "us", "ms", "s" };
    char **row_names =
        ensure_timeline_names(_mesa_hash_table_num_entries(state->hw_contexts_table));
    uint32_t n_rows = 0;
    list_for_each_entry(struct hw_context, context, &state->hw_contexts, link)
        row_names[n_rows++] = context->name;
    int n_tps = list_length(&state->perf_tracepoints);
    Gputop::BeginTimeline("i915-perf-timeline", n_rows, n_tps,
                          end_ts - start_ts,
                          ImVec2(ImGui::GetContentRegionAvailWidth(), 300.0f));

    uint32_t n_entries = 0;
    list_for_each_entry(struct accumulated_samples, samples, &state->timelines, link) {
        if (samples->timestamp_end < start_ts)
            continue;
        if (samples->timestamp_start > end_ts)
            break;

        n_entries++;
        assert(samples->context->timeline_row < n_rows);

        if (Gputop::TimelineItem(samples->context->timeline_row,
                                 MAX2(samples->timestamp_start, start_ts) - start_ts,
                                 samples->timestamp_end - start_ts, false)) {
            memcpy(&window->selected_samples, samples, sizeof(window->selected_samples));
            memcpy(&window->selected_context, samples->context,
                   sizeof(window->selected_context));

            char time_length[20];
            pretty_print_value(GPUTOP_PERFQUERY_COUNTER_UNITS_NS,
                               samples->timestamp_end - samples->timestamp_start,
                               time_length, sizeof(time_length));
            ImGui::SetTooltip("%s : %s",
                              samples->context->name, time_length);
        }
    }

    list_for_each_entry(struct perf_tracepoint_data, data, &state->perf_tracepoints_data, link) {
        if (data->data.time < start_ts)
            continue;
        if (data->data.time > end_ts)
            break;

        if (Gputop::TimelineEvent(data->tp->idx,
                                  MAX2(data->data.time, start_ts) - start_ts,
                                  data->data.time == window->tracepoint_selected_ts)) {
            char point_desc[200];
            print_tracepoint_data(point_desc, sizeof(point_desc), data, false);
            ImGui::SetTooltip("%s:\ncpu:%i\n%s", data->tp->name, data->cpu, point_desc);

            memcpy(&window->tracepoint, data->tp, sizeof(window->tracepoint));
            // memcpy(&window->tracepoint_data, data, sizeof(window->tracepoint_data));
        }
    }


    int64_t zoom_start;
    uint64_t zoom_end;
    if (Gputop::EndTimeline(units, ARRAY_SIZE(units),
                            (const char **) row_names,
                            &zoom_start, &zoom_end)) {
        window->zoom_start = MAX2(window->zoom_length == 0 ?
                                  zoom_start : window->zoom_start + zoom_start,
                                  0);
        window->zoom_length = MIN2(zoom_end - zoom_start, max_length);
    }
}

// static void
// display_perf_timeline_window(struct timeline_window *window,
//                              struct connection_state *state)
// {
//     const uint64_t max_length = state->oa_visible_timeline_s * 1000000000ULL;
//     int n_tps = list_length(&state->perf_tracepoints);
//     uint64_t start_ts, end_ts;

//     get_timeline_bounds(window, state, &start_ts, &end_ts);

//     Gputop::BeginTimeline("perf-timeline", 0, n_tps,
//                           end_ts - start_ts,
//                           ImVec2(ImGui::GetContentRegionAvailWidth(), 100.0f));

//     list_for_each_entry(struct perf_tracepoint_data, data, &state->perf_tracepoints_data, link) {
//         if (data->data.time < start_ts)
//             continue;
//         if (data->data.time > end_ts)
//             break;

//         if (Gputop::TimelineEvent(data->tp->idx,
//                                   MAX2(data->data.time, start_ts) - start_ts)) {
//             char point_desc[200];
//             print_tracepoint_data(point_desc, sizeof(point_desc), data);
//             ImGui::SetTooltip("%s:\ncpu:%i\n%s", data->tp->name, data->cpu, point_desc);

//             memcpy(&window->tracepoint, data->tp, sizeof(window->tracepoint));
//             // memcpy(&window->tracepoint_data, data, sizeof(window->tracepoint_data));
//         }
//     }

//     static const char *units[] = { "ns", "us", "ms", "s" };
//     int64_t zoom_start;
//     uint64_t zoom_end;
//     if (Gputop::EndTimeline(units, ARRAY_SIZE(units), NULL,
//                             &zoom_start, &zoom_end)) {
//         window->zoom_start = MAX2(window->zoom_length == 0 ?
//                                   zoom_start : window->zoom_start + zoom_start,
//                                   0);
//         window->zoom_length = MIN2(zoom_end - zoom_start, max_length);
//     }
// }

static void
display_timeline_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;
    struct timeline_window *window = (struct timeline_window *) win;

    display_i915_perf_timeline_window(window, state);
    // display_perf_timeline_window(window, state);

    ImGui::Columns(2);
    int n_contexts = _mesa_hash_table_num_entries(state->hw_contexts_table);
    ImGui::ColorButton("##selected_context",
                       Gputop::GetTimelineRowColor(window->selected_context.timeline_row, n_contexts),
                       ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoTooltip); ImGui::SameLine();
    ImGui::Text("hw_id : 0x%x", window->selected_context.hw_id); ImGui::SameLine();
    static ImGuiTextFilter filter;
    filter.Draw();
    if (state->metric_set) {
        ImGui::BeginChild("##counters");
        for (int c = 0; c < state->metric_set->n_counters; c++) {
            const struct gputop_metric_set_counter *counter =
                &state->metric_set->counters[c];
            if (!filter.PassFilter(counter->name)) continue;
            double value = read_counter_value(state, &window->selected_samples, counter);
            char svalue[100];
            pretty_print_counter_value(counter, value, svalue, sizeof(svalue));
            ImGui::Text("%s : %s", counter->name, svalue);
        }
        ImGui::EndChild();
    }

    ImGui::NextColumn();
    ImGui::BeginChild("##data-samples");
    uint64_t start_ts, end_ts;
    get_timeline_bounds(window, state, &start_ts, &end_ts);

    int n_tps = list_length(&state->perf_tracepoints);
    window->tracepoint_selected_ts = 0ULL;
    list_for_each_entry(struct perf_tracepoint_data, data, &state->perf_tracepoints_data, link) {
        if (data->data.time < start_ts)
            continue;
        if (data->data.time > end_ts)
            break;

        char desc[20];
        snprintf(desc, sizeof(desc), "##%p", data);
        ImGui::ColorButton(desc,
                           Gputop::GetTimelineRowColor(data->tp->idx, n_tps),
                           ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoTooltip); ImGui::SameLine();
        char point_desc[200];
        print_tracepoint_data(point_desc, sizeof(point_desc), data, true);
        ImGui::Selectable(point_desc);
        if (ImGui::IsItemHovered()) window->tracepoint_selected_ts = data->data.time;

        if (!ImGui::IsItemVisible())
            break;
    }
    ImGui::EndChild();

}

static void
display_timeline_reports(struct window *win)
{
    struct timeline_window *window = (struct timeline_window *) container_of(win, window, reports_window);
    struct connection_state *state = &context.connection_state;

    if (state->is_sampling)
        return;

    ImGui::BeginChild("##reports");
    display_accumulated_reports(state, &window->selected_samples);
    ImGui::EndChild();
}


static void
show_timeline_window(void)
{
    struct timeline_window *window = &context.timeline_window;

    if (window->base.opened) {
        window->base.opened = false;
        window->reports_window.opened = false;
        return;
    }

    snprintf(window->base.name, sizeof(window->base.name),
             "i915 OA timeline##%p", window);
    window->base.size = ImVec2(800, 400);
    window->base.display = display_timeline_window;
    window->base.destroy = hide_window;
    window->base.opened = true;

    snprintf(window->reports_window.name, sizeof(window->reports_window.name),
             "i915 perf reports##%p", &window->reports_window);
    window->reports_window.size = ImVec2(400, 800);
    window->reports_window.display = display_timeline_reports;
    window->reports_window.destroy = hide_window;
    window->reports_window.opened = false;

    window->zoom_start = 0;
    struct connection_state *state = &context.connection_state;
    window->zoom_length = state->oa_visible_timeline_s * 1000000000ULL;

    list_add(&window->base.link, &context.windows);
}

/**/

static void
display_tracepoints_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    ImGui::Columns(3);

    ImGui::BeginChild("##column1");
    ImGui::Text("Available tracepoints");
    ImGui::Separator();
    static ImGuiTextFilter filter;
    filter.Draw();
    ImGui::BeginChild("##tracepoints");
    if (state->features) {
        for (unsigned i = 0; i < state->features->features->n_tracepoints; i++) {
            if (filter.PassFilter(state->features->features->tracepoints[i]) &&
                ImGui::Selectable(state->features->features->tracepoints[i])) {
                if (!_mesa_hash_table_search(state->perf_tracepoints_name_table,
                                             state->features->features->tracepoints[i]))
                    new_tracepoint(state, state->features->features->tracepoints[i]);
            }
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();

    ImGui::NextColumn();
    ImGui::BeginChild("##column2");
    ImGui::Text("Tracepoint format");
    ImGui::Separator();
    if (state->tracepoint_info) {
        ImGui::Text("event_id=%u", state->tracepoint_info->tracepoint_info->event_id);
        ImGui::InputTextMultiline("##format",
                                  state->tracepoint_info->tracepoint_info->sample_format,
                                  strlen(state->tracepoint_info->tracepoint_info->sample_format),
                                  ImGui::GetContentRegionAvail(),
                                  ImGuiInputTextFlags_ReadOnly);
    }
    ImGui::EndChild();

    ImGui::NextColumn();
    ImGui::BeginChild("##column3");
    ImGui::Text("Selected tracepoints");
    ImGui::Separator();
    list_for_each_entry_safe(struct perf_tracepoint, tp, &state->perf_tracepoints, link) {
        if (ImGui::Selectable(tp->name)) {
            destroy_perf_tracepoint(state, tp);
        }
    }
    ImGui::EndChild();
}

static void
show_tracepoints_window(void)
{
    struct window *window = &context.tracepoints_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name),
             "Tracepoints##%p", window);
    window->size = ImVec2(800, 300);
    window->display = display_tracepoints_window;
    window->destroy = hide_window;
    window->opened = true;

    list_add(&window->link, &context.windows);
}

/**/

static void
display_events_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    ImGui::Text("Available events");
    ImGui::Separator();
    static ImGuiTextFilter filter;
    filter.Draw();
    ImGui::BeginChild("##events");
    if (state->features) {
        for (unsigned i = 0; i < state->features->features->n_events; i++) {
            if (filter.PassFilter(state->features->features->events[i]) &&
                ImGui::Selectable(state->features->features->events[i])) {
            }
        }
    }
    ImGui::EndChild();
}

static void
show_events_window(void)
{
    struct window *window = &context.tracepoints_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name),
             "Events##%p", window);
    window->size = ImVec2(800, 300);
    window->display = display_events_window;
    window->destroy = hide_window;
    window->opened = true;

    list_add(&window->link, &context.windows);
}

/**/

static void
display_log_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    if (ImGui::Button("Clear")) clear_logs(state);

    ImGui::BeginChild(ImGui::GetID("##block"));
    for (int i = 0; i < state->n_messages; i++) {
        int idx = (state->start_message + i) % ARRAY_SIZE(state->messages);
        ImGui::Text(state->messages[idx].msg);
    }
    ImGui::EndChild();
}

static void
show_log_window(void)
{
    struct window *window = &context.log_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name), "Server logs");
    window->size = ImVec2(400, 200);
    window->display = display_log_window;
    window->opened = true;
    window->destroy = hide_window;

    list_add(&window->link, &context.windows);
}

/**/

static void
display_style_editor_window(struct window *win)
{
    ImGuiColorEditFlags cflags = (ImGuiColorEditFlags_NoAlpha |
                                  ImGuiColorEditFlags_NoInputs);
    ImGui::ColorEdit3("background", (float *)&context.clear_color, cflags);
    Gputop::DisplayColorsProperties();
}

static void
show_style_editor_window(void)
{
    struct window *window = &context.style_editor_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name), "Style editor");
    window->size = ImVec2(400, 200);
    window->display = display_style_editor_window;
    window->opened = true;
    window->destroy = hide_window;

    list_add(&window->link, &context.windows);
}

/**/

static void
display_streams_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    ImGui::Columns(2);
    ImGui::Text("Streams:");
    list_for_each_entry(struct stream, stream, &state->streams, link) {
        ImGui::Text("id=%i", stream->id); ImGui::SameLine();
        ImGui::ProgressBar(stream->fill / 100.0);
    }
    ImGui::NextColumn();
    list_for_each_entry(struct perf_tracepoint, tp, &state->perf_tracepoints, link) {
        ImGui::Text("tp=%s id=%i", tp->name, tp->event_id);
    }
    ImGui::Text("n_timelines=%i", state->n_timelines);
    ImGui::Text("n_graphs=%i", state->n_graphs);
    ImGui::Text("n_cpu_stats=%i", state->n_cpu_stats);

    list_for_each_entry(struct perf_tracepoint_data, data, &state->perf_tracepoints_data, link) {
        ImGui::Text("%s time=%lx", data->tp->name, data->data.time);
    }
}

static void
show_streams_window(void)
{
    struct window *window = &context.streams_window;

    if (window->opened) {
        window->opened = false;
        return;
    }

    snprintf(window->name, sizeof(window->name), "Streams");
    window->size = ImVec2(400, 200);
    window->display = display_streams_window;
    window->opened = true;
    window->destroy = hide_window;

    list_add(&window->link, &context.windows);
}

/**/

static float *
get_cpus_stats(struct connection_state *state, int max_cpu_stats)
{
    int n_cpus = state->features ? state->features->features->n_cpus : 1;
    float *values = ensure_plot_accumulator(n_cpus * max_cpu_stats);
    int i;

    for (i = 0; i < max_cpu_stats - state->n_cpu_stats; i++) {
        for (int cpu = 0; cpu < n_cpus; cpu++)
            values[n_cpus * i + cpu] = 0.0f;
    }

    struct cpu_stat *stat = list_first_entry(&state->cpu_stats,
                                             struct cpu_stat, link);
    for (; i < (max_cpu_stats - 1); i++) {
        struct cpu_stat *next = list_first_entry(&stat->link,
                                                 struct cpu_stat, link);
        assert(&next->link != &state->cpu_stats);

        for (int cpu = 0; cpu < n_cpus; cpu++) {
            Gputop__CpuStats *cpu_stat0 = stat->stat->cpu_stats->cpus[cpu];
            Gputop__CpuStats *cpu_stat1 = next->stat->cpu_stats->cpus[cpu];
            uint32_t total = ((cpu_stat1->user       - cpu_stat0->user) +
                              (cpu_stat1->nice       - cpu_stat0->nice) +
                              (cpu_stat1->system     - cpu_stat0->system) +
                              (cpu_stat1->idle       - cpu_stat0->idle) +
                              (cpu_stat1->iowait     - cpu_stat0->iowait) +
                              (cpu_stat1->irq        - cpu_stat0->irq) +
                              (cpu_stat1->softirq    - cpu_stat0->softirq) +
                              (cpu_stat1->steal      - cpu_stat0->steal) +
                              (cpu_stat1->guest      - cpu_stat0->guest) +
                              (cpu_stat1->guest_nice - cpu_stat0->guest_nice));
            if (total == 0)
                values[n_cpus * i + cpu] = 0.0f;
            else {
                values[n_cpus * i + cpu] =
                    100.0f - 100.f * (float) (cpu_stat1->idle - cpu_stat0->idle) / total;
            }
        }

        stat = next;
    }

    return values;
}

struct cpu_stat_getter {
    float *values;
    int n_cpus;
};

static float
get_cpu_stat_item(void *data, int line, int idx)
{
    struct cpu_stat_getter *getter = (struct cpu_stat_getter *) data;

    return getter->values[idx * getter->n_cpus + line];
}

static void
display_cpu_stats(void)
{
    struct connection_state *state = &context.connection_state;
    int n_cpus = state->features ? state->features->features->n_cpus : 1;
    int max_cpu_stats =
        (int) (state->cpu_stats_visible_timeline_s * 1000.0f) /
        state->cpu_stats_sampling_period_ms;

    struct cpu_stat_getter getter = { get_cpus_stats(state, max_cpu_stats), n_cpus };
    char title[20];
    snprintf(title, sizeof(title), "%i CPU(s)", n_cpus);
    Gputop::PlotMultilines("",
                           &get_cpu_stat_item, &getter,
                           n_cpus, max_cpu_stats - 1, 0,
                           context.cpu_colors,
                           title, 0.0f, 100.0f,
                           ImVec2(ImGui::GetContentRegionAvailWidth(), 100.0f));
}

static bool
select_metric_set(struct connection_state *state,
                  const struct gputop_metric_set **out_metric_set)
{
    bool selected = false;
    static ImGuiTextFilter filter;
    filter.Draw();

    if (!state->features) return false;

    ImGui::BeginChild("##block");
    for (unsigned u = 0; u < state->features->features->n_supported_oa_uuids; u++) {
        const struct gputop_metric_set *metric_set =
            uuid_to_metric_set(state->features->features->supported_oa_uuids[u]);
        if (!metric_set) continue;

        if (filter.PassFilter(metric_set->name) &&
            ImGui::Selectable(metric_set->name)) {
            *out_metric_set = metric_set;
            selected = true;
        }
    }
    ImGui::EndChild();

    return selected;
}

static bool
select_metric_set_from_counter(struct connection_state *state,
                               const struct gputop_metric_set **out_metric_set)
{
    bool selected = false;
    static ImGuiTextFilter filter;
    filter.Draw();

    if (!state->features) return false;

    ImGui::BeginChild("##block");
    for (unsigned u = 0; u < state->features->features->n_supported_oa_uuids; u++) {
        const struct gputop_metric_set *metric_set =
            uuid_to_metric_set(state->features->features->supported_oa_uuids[u]);
        if (!metric_set) continue;

        for (int c = 0; c < metric_set->n_counters; c++) {
            const struct gputop_metric_set_counter *counter =
                &metric_set->counters[c];
            char name[200];
            snprintf(name, sizeof(name), "%s / %s",
                     metric_set->name, counter->name);

            if (filter.PassFilter(counter->name) &&
                ImGui::Selectable(name)) {
                *out_metric_set = metric_set;
                selected = true;
            }
        }
    }
    ImGui::EndChild();

    return selected;
}

static void
display_main_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;
    char name[20];

    if (ImGui::Button("Style editor")) { show_style_editor_window(); } ImGui::SameLine();
    if (state->n_messages > 0)
        snprintf(name, sizeof(name), "Logs (%i)", state->n_messages);
    else
        snprintf(name, sizeof(name), "Logs");
    if (ImGui::Button(name)) { show_log_window(); } ImGui::SameLine();
    if (ImGui::Button("Report")) { show_report_window(); } ImGui::SameLine();
    if (ImGui::Button("Streams")) { show_streams_window(); }

    if (ImGui::InputText("Address", state->host_address,
                         sizeof(state->host_address),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
        reconnect();
    }
    if (ImGui::InputInt("Port", &state->host_port, 1, 100,
                        ImGuiInputTextFlags_EnterReturnsTrue)) {
        reconnect();
    }
    if (ImGui::Button("Connect")) { reconnect(); } ImGui::SameLine();
    ImGui::Text("Status:"); ImGui::SameLine();
    bool is_connected = (state->connection &&
                         gputop_connection_connected(state->connection));
    ImColor color = is_connected ? ImColor(0.0f, 1.0f, 0.0f) : ImColor(0.9f, 0.0f, 0.0f);
    const char *connection_status = state->connection ?
        (is_connected ? "Connected" : "Connecting...") :
        (state->connection_error ? state->connection_error : "Not connected");
    ImGui::TextColored(color, connection_status);

    /* CPU */
    ImGui::Separator();
    if (state->features) {
        ImGui::Text("CPU model: %s", state->features->features->cpu_model);
        ImGui::Text("Kernel release: %s", state->features->features->kernel_release);
        ImGui::Text("Kernel build: %s", state->features->features->kernel_build);
    }
    int vcpu = state->cpu_stats_sampling_period_ms;
    if (ImGui::InputInt("CPU sampling period (ms)", &vcpu)) {
        vcpu = CLAMP(vcpu, 1, 1000);
        if (vcpu != state->cpu_stats_sampling_period_ms) { reopen_cpu_stats_stream(vcpu); }
    }
    ImGui::SliderFloat("CPU visible sampling (s)",
                       &state->cpu_stats_visible_timeline_s, 0.1f, 15.0f);
    if (ImGui::Button("Select events")) { show_events_window(); } ImGui::SameLine();
    if (ImGui::Button("Select tracepoints")) { show_tracepoints_window(); }
    display_cpu_stats();


    /* GPU */
    ImGui::Separator();
    if (state->features) {
        const Gputop__DevInfo *devinfo = state->features->features->devinfo;
        ImGui::Text("GT name: %s (Gen %u, PCI 0x%x)",
                    devinfo->prettyname, devinfo->gen, devinfo->devid);
        ImGui::Text("%llu threads, %llu EUs, %llu slices, %llu subslices",
                    devinfo->eu_threads_count, devinfo->n_eus,
                    devinfo->n_eu_slices, devinfo->n_eu_sub_slices);
        ImGui::Text("GT frequency range %.1fMHz / %.1fMHz",
                    (double) devinfo->gt_min_freq / 1000000.0f,
                    (double) devinfo->gt_max_freq / 1000000.0f);
        ImGui::Text("CS timestamp frequency %lu Hz / %.2f ns",
                    devinfo->timestamp_frequency,
                    1000000000.0f / devinfo->timestamp_frequency);

        bool open_popup = ImGui::Button("Select metric");
        if (open_popup)
            ImGui::OpenPopup("metric picker");
        ImGui::SetNextWindowSize(ImVec2(400, 400));
        if (ImGui::BeginPopup("metric picker")) {
            if (select_metric_set(state, &state->metric_set))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        } ImGui::SameLine();
        open_popup = ImGui::Button("Select metric set from counter");
        if (open_popup)
            ImGui::OpenPopup("metric counter picker");
        ImGui::SetNextWindowSize(ImVec2(600, 400));
        if (ImGui::BeginPopup("metric counter picker")) {
            if (select_metric_set_from_counter(state, &state->metric_set))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        } ImGui::SameLine();
        ImColor color = state->metric_set ? ImColor(0.0f, 1.0f, 0.0f) : ImColor(0.9f, 0.0f, 0.0f);
        ImGui::TextColored(color,
                           state->metric_set ? state->metric_set->name : "No metric set selected");
    }
    int oa_sampling_period_ms = state->oa_aggregation_period_ms;
    if (ImGui::InputInt("OA sampling period (ms)", &oa_sampling_period_ms))
        state->oa_aggregation_period_ms = CLAMP(oa_sampling_period_ms, 1, 1000);
    ImGui::SliderFloat("OA visible sampling (s)",
                       &state->oa_visible_timeline_s, 0.1f, 15.0f);
    if (ImGui::Button("New counter window")) { new_i915_perf_window(); } ImGui::SameLine();
    if (ImGui::Button("Timeline")) { show_timeline_window(); } ImGui::SameLine();
    if (ImGui::Button(state->is_sampling ? "Stop sampling" : "Start sampling")) {
        if (state->is_sampling)
            stop_sampling(state);
        else
            start_sampling(state);
    }

    if (state->features) {
        static bool show_topology = true;
        ImGui::Checkbox("Show topology", &show_topology);
        if (show_topology) {
            ImGui::BeginChild("##topology");
            const Gputop__DevInfo *devinfo = state->features->features->devinfo;

            const char *engine_names[] = {
                "other", "rcs", "blt", "vcs", "vecs",
            };
            int engines[ARRAY_SIZE(devinfo->topology->engines)];
            for (int e = 0; e < devinfo->topology->n_engines; e++) {
                engines[e] = devinfo->topology->engines[e];
            }
            assert(devinfo->topology->n_engines <= ARRAY_SIZE(engine_names));
            Gputop::EngineTopology("##engines",
                                   devinfo->topology->n_engines, engines,
                                   engine_names,
                                   ImGui::GetWindowContentRegionWidth());
            Gputop::RcsTopology("##topology",
                                devinfo->topology->n_slices,
                                devinfo->topology->n_subslices,
                                devinfo->topology->n_eus_per_subslice,
                                devinfo->topology->slices_mask.data,
                                devinfo->topology->subslices_mask.data,
                                devinfo->topology->eus_mask.data,
                                ImGui::GetWindowContentRegionWidth());
            ImGui::EndChild();
        }
    }
}

static void
show_main_window(void)
{
    struct window *window = &context.main_window;

    if (window->opened)
        return;

    snprintf(window->name, sizeof(window->name), "GPUTop");
    window->size = ImVec2(-1, 200);
    window->position =
        ImVec2(0, ImGui::GetIO().DisplaySize.y - window->size.y);
    window->opened = true;
    window->display = display_main_window;
    window->destroy = NULL;

    list_add(&window->link, &context.windows);
}

/**/

static void
display_windows(void)
{
    list_for_each_entry(struct window, window, &context.windows, link) {
        ImGui::SetNextWindowPos(window->position, ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(window->size, ImGuiCond_FirstUseEver);

        ImGui::Begin(window->name, &window->opened);
        window->display(window);
        window->position = ImGui::GetWindowPos();
        window->size = ImGui::GetWindowSize();
        ImGui::End();
    }

    list_for_each_entry_safe(struct window, window, &context.windows, link) {
        if (window->opened) continue;

        if (window->destroy) {
            list_del(&window->link);
            window->destroy(window);
        } else
            window->opened = true;
    }
}

static void
init_ui(const char *host, int port)
{
    memset(&context.connection_state, 0, sizeof(context.connection_state));

    list_inithead(&context.windows);
    list_inithead(&context.i915_perf_windows);

    context.clear_color = ImColor(114, 144, 154);

    list_inithead(&context.connection_state.cpu_stats);
    context.connection_state.cpu_stats_visible_timeline_s = 3.0f;
    context.connection_state.cpu_stats_sampling_period_ms = 100;

    context.connection_state.oa_visible_timeline_s = 7.0f;
    context.connection_state.oa_aggregation_period_ms = 50;

    snprintf(context.connection_state.host_address,
             sizeof(context.connection_state.host_address),
             host ? host : "localhost");
    context.connection_state.host_port = port != 0 ? port : 7890;

    context.connection_state.metrics_map =
        _mesa_hash_table_create(NULL, _mesa_hash_string, _mesa_key_string_equal);
    context.connection_state.hw_contexts_table =
        _mesa_hash_table_create(NULL, _mesa_hash_pointer, _mesa_key_pointer_equal);

    list_inithead(&context.connection_state.graphs);
    list_inithead(&context.connection_state.timelines);
    list_inithead(&context.connection_state.free_samples);
    list_inithead(&context.connection_state.i915_perf_chunks);

    list_inithead(&context.connection_state.perf_tracepoints);
    list_inithead(&context.connection_state.perf_tracepoints_data);
    context.connection_state.perf_tracepoints_name_table =
        _mesa_hash_table_create(NULL, _mesa_hash_string, _mesa_key_string_equal);
    context.connection_state.perf_tracepoints_uuid_table =
        _mesa_hash_table_create(NULL, _mesa_hash_string, _mesa_key_string_equal);
    context.connection_state.perf_tracepoints_stream_table =
        _mesa_hash_table_create(NULL, _mesa_hash_pointer, _mesa_key_pointer_equal);

    context.connection_state.processes_table =
        _mesa_hash_table_create(NULL, _mesa_hash_pointer, _mesa_key_pointer_equal);

    reset_connection_state();

    Gputop::InitColorsProperties();

    if (host != NULL)
        reconnect();
}

/**/

static void
repaint_window(CoglOnscreen *onscreen, gpointer user_data)
{
    ImGui_ImplGtk3Cogl_NewFrame();

    show_main_window();

    display_windows();

    /* Rendering */
    {
        CoglFramebuffer *fb = COGL_FRAMEBUFFER(onscreen);
        cogl_framebuffer_set_viewport(fb,
                                      0, 0,
                                      cogl_framebuffer_get_width(fb),
                                      cogl_framebuffer_get_height(fb));

        cogl_framebuffer_clear4f(fb, COGL_BUFFER_BIT_COLOR | COGL_BUFFER_BIT_DEPTH,
                                 context.clear_color.x,
                                 context.clear_color.y,
                                 context.clear_color.z, 1.0);
        ImGui::Render();
        cogl_onscreen_swap_buffers(onscreen);
    }
}

/* Native part */

#include <libsoup/soup.h>

int
main(int argc, char *argv[])
{
    g_autofree gchar *host = NULL;
    GOptionEntry entries[] = {
        { "host", 'h', 0, G_OPTION_ARG_STRING, &host },
        { NULL }
    };

    gtk_init(&argc, &argv);

    g_autoptr(GOptionContext) context = NULL;
    context = g_option_context_new(NULL);
    g_option_context_set_ignore_unknown_options(context, TRUE);
    g_option_context_set_help_enabled(context, FALSE);
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_parse(context, &argc, &argv, NULL);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "GPUTop");
    g_signal_connect(window, "delete-event", G_CALLBACK(gtk_main_quit), NULL);
    gtk_window_resize(GTK_WINDOW(window), 1024, 768);

    GtkWidget *box = gtk_event_box_new();
    gtk_widget_set_can_focus(box, TRUE);
    gtk_container_add(GTK_CONTAINER(window), box);
    gtk_widget_show_all(window);

    CoglOnscreen *onscreen = ImGui_ImplGtk3Cogl_Init(box, repaint_window, NULL);

    if (host) {
        g_autofree gchar *url = g_strdup_printf("gputop://%s", host);
        g_autoptr(SoupURI) uri = soup_uri_new(url);
        init_ui(soup_uri_get_host(uri), soup_uri_get_port(uri));
    } else
        init_ui(NULL, 0);

    gtk_main();

    return EXIT_SUCCESS;
}
