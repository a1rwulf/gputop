#include <stdlib.h>

#include "imgui.h"
#include "imgui_impl_gtk3_cogl.h"

#include "util/hash_table.h"
#include "util/list.h"

#include "gputop.pb-c.h"
#include "gputop-oa-counters.h"
#include "gputop-soup-network.h"

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

struct accumulated_samples {
    struct list_head link;

    uint32_t pid;

    uint64_t deltas[MAX_RAW_OA_COUNTERS];
};

struct cpu_stat {
    struct list_head link;

    Gputop__Message *stat;
};

struct connection_state {
    char host_address[100];
    int host_port;
    gputop_connection_t *connection;
    char *connection_error;

    /**/
    Gputop__Message *features;

    struct hash_table *metrics_map;
    struct gputop_devinfo devinfo;

    int selected_uuid;

    /**/
    list_head cpu_stats;
    int n_cpu_stats;
    float cpu_stats_visible_timeline_s;
    int cpu_stats_sampling_period_ms;
    int cpu_stats_stream_id;

    /**/
    struct gputop_cc_oa_accumulator accumulator;
    const struct gputop_metric_set *metric_set;
    uint8_t last_report[256];
    int oa_stream_id;

    /**/
    struct list_head graph;
    int n_graph;
    float oa_visible_timeline_s;
    uint32_t oa_aggregation_period_ms;

    /**/
    struct list_head timeline;
    int n_timeline;

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
    float *plot_accumulator;
    int n_plot_accumulator;
};

struct i915_perf_counter {
    struct list_head link;

    const struct gputop_metric_set_counter *counter;
    double latest_max;
};

struct i915_perf_window {
    struct window base;

    struct list_head link;
    struct list_head counters;
};

static struct {
    /**/
    struct connection_state connection_state;

    /* UI */
    struct list_head windows;
    struct list_head i915_perf_windows;

    struct window main_window;
    struct window log_window;

    ImVec4 clear_color;
    ImVec4 graph_color;
    ImVec4 cpu_stats_color;
} context;

/**/

static float *
ensure_plot_accumulator(int length)
{
    struct connection_state *state = &context.connection_state;

    if (state->n_plot_accumulator < length) {
        state->n_plot_accumulator = length;
        state->plot_accumulator = (float *)
            realloc(state->plot_accumulator, state->n_plot_accumulator * sizeof(float));
    }

    return state->plot_accumulator;
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
reset_connection_state(void)
{
    struct connection_state *state = &context.connection_state;

    /**/
    gputop__message__free_unpacked(state->features, NULL);
    state->features = NULL;

    _mesa_hash_table_clear(state->metrics_map, NULL);

    state->selected_uuid = -1;
    state->oa_stream_id = -1;

    /**/
    list_inithead(&state->graph);
    list_inithead(&state->timeline);

    state->n_graph = 0;

    state->n_messages = 0;
}

/**/

static void
i915_perf_record_for_time(struct connection_state *state,
                          struct gputop_cc_oa_accumulator *accumulator)
{
    struct accumulated_samples *samples;
    uint32_t max_graphs =
        (state->oa_visible_timeline_s * 1000.0f) / state->oa_aggregation_period_ms;

    /* Remove excess of samples */
    while (state->n_graph > max_graphs) {
        samples = list_first_entry(&state->graph, struct accumulated_samples, link);
        list_del(&samples->link);
        free(samples);
        state->n_graph--;
    }

    if (state->n_graph < max_graphs) {
        samples = (struct accumulated_samples *) malloc(sizeof(*samples));
        list_addtail(&samples->link, &state->graph);
        state->n_graph++;
    } else {
        samples = list_first_entry(&state->graph,
                                   struct accumulated_samples, link);
        list_del(&samples->link);
        list_addtail(&samples->link, &state->graph);
    }

    memcpy(samples->deltas, accumulator->deltas, sizeof(samples->deltas));

    ImGui_ImplGtk3Cogl_ScheduleFrame();
}

static void
i915_perf_accumulate_for_time(const uint8_t *data, size_t len)
{
    struct connection_state *state = &context.connection_state;
    const struct drm_i915_perf_record_header *header;
    const uint8_t *last = state->last_report;

    for (header = (const struct drm_i915_perf_record_header *) data;
         (const uint8_t *) header < (data + len);
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
            const uint8_t *samples = (const uint8_t *) (header + 1);

            if (last) {
                struct gputop_cc_oa_accumulator *accumulator =
                    &state->accumulator;

                if (gputop_cc_oa_accumulate_reports(accumulator, last, samples)) {
                    uint64_t elapsed = (accumulator->last_timestamp -
                                        accumulator->first_timestamp);
                    uint32_t events = 0;

                    if (elapsed > (state->oa_aggregation_period_ms * 1000000ULL)) {
                        i915_perf_record_for_time(state, accumulator);
                        gputop_cc_oa_accumulator_clear(accumulator);
                    }
                }
            }

            last = samples;
            break;
        }

        default:
            g_warning("i915 perf: Spurious header type = %d", header->type);
            return;
        }
    }

    memcpy(state->last_report, last, sizeof(state->last_report));
}

static void
i915_perf_accumulate_for_context(const uint8_t *data, size_t len)
{
    struct connection_state *state = &context.connection_state;
    const struct drm_i915_perf_record_header *header;
    const uint8_t *last = state->last_report;

    for (header = (const struct drm_i915_perf_record_header *) data;
         (const uint8_t *) header < (data + len);
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
            const uint8_t *samples = (const uint8_t *) (header + 1);

            if (last) {
                struct gputop_cc_oa_accumulator *accumulator =
                    &state->accumulator;

                if (gputop_cc_oa_accumulate_reports(accumulator, last, samples)) {
                    uint64_t elapsed = (accumulator->last_timestamp -
                                        accumulator->first_timestamp);
                    uint32_t events = 0;

                    if (elapsed > (state->oa_aggregation_period_ms * 1000000ULL)) {
                        i915_perf_record_for_time(state, accumulator);
                        gputop_cc_oa_accumulator_clear(accumulator);
                    }
                }
            }

            last = samples;
            break;
        }

        default:
            g_warning("i915 perf: Spurious header type = %d", header->type);
            return;
        }
    }

    memcpy(state->last_report, last, sizeof(state->last_report));
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
    };
    struct connection_state *state = &context.connection_state;

    state->devinfo.timestamp_frequency = devinfo->timestamp_frequency;
    state->devinfo.devid = devinfo->devid;
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

static void
close_stream(uint32_t stream_id)
{
    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_CLOSE_STREAM;
    request.close_stream = stream_id;

    send_pb_message(&request.base);
}

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
maybe_close_i915_perf_stream(void)
{
    struct connection_state *state = &context.connection_state;

    if (list_length(&context.i915_perf_windows) >= 1 ||
        state->oa_stream_id < 0)
        return;

    close_stream(state->oa_stream_id);
    state->oa_stream_id = -1;
}

static void
open_i915_perf_stream(int sampling_period)
{
    struct connection_state *state = &context.connection_state;

    if (!state->metric_set) {
        g_warning("No metric set selected");
        return;
    }

    state->oa_aggregation_period_ms = sampling_period;
    gputop_cc_oa_accumulator_init(&state->accumulator,
                                  &state->devinfo,
                                  state->metric_set,
                                  false,
                                  state->oa_aggregation_period_ms * 1000000);

    Gputop__OAStreamInfo oa_stream = GPUTOP__OASTREAM_INFO__INIT;
    oa_stream.uuid = (char *) state->metric_set->hw_config_guid;
    oa_stream.period_exponent =
        period_to_oa_exponent(state, state->oa_aggregation_period_ms);
    oa_stream.per_ctx_mode = false;

    Gputop__OpenStream stream = GPUTOP__OPEN_STREAM__INIT;
    stream.id = state->oa_stream_id = state->stream_id++;
    g_message("selected stream_id=%i", state->oa_stream_id);
    stream.overwrite = false;
    stream.live_updates = true;
    stream.type_case = GPUTOP__OPEN_STREAM__TYPE_OA_STREAM;
    stream.oa_stream = &oa_stream;

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_OPEN_STREAM;
    request.open_stream = &stream;

    send_pb_message(&request.base);
}

static void
maybe_open_i915_perf_stream(void)
{
    struct connection_state *state = &context.connection_state;

    if (list_length(&context.i915_perf_windows) < 1 ||
        !state->metric_set ||
        state->oa_stream_id >= 0)
        return;

    open_i915_perf_stream(state->oa_aggregation_period_ms);
}

static void
maybe_reopen_i915_perf_stats_stream(int sampling_period)
{
    struct connection_state *state = &context.connection_state;

    if (state->oa_stream_id < 0)
        return;

    close_stream(state->oa_stream_id);
    state->oa_stream_id = -1;

    open_i915_perf_stream(sampling_period);
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

static bool
cpu_stats_add(Gputop__Message *message)
{
    struct connection_state *state = &context.connection_state;
    if (message->cpu_stats->id != state->cpu_stats_stream_id)
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
    stream.id = state->cpu_stats_stream_id = state->stream_id++;
    stream.overwrite = false;
    stream.live_updates = true;
    stream.type_case = GPUTOP__OPEN_STREAM__TYPE_CPU_STATS;
    stream.cpu_stats = &cpu_stats;

    Gputop__Request request = GPUTOP__REQUEST__INIT;
    request.req_case = GPUTOP__REQUEST__REQ_OPEN_STREAM;
    request.open_stream = &stream;

    send_pb_message(&request.base);
}

static void
reopen_cpu_stats_stream(int sampling_period_ms)
{
    struct connection_state *state = &context.connection_state;

    if (state->cpu_stats_stream_id >= 0) {
        close_stream(state->cpu_stats_stream_id);
        state->cpu_stats_stream_id = -1;
    }
    open_cpu_stats_stream(sampling_period_ms);
}

/**/

static void
handle_perf_data(const uint8_t *data, size_t len)
{

}

static void
handle_i915_perf_data(const uint8_t *data, size_t len)
{
    i915_perf_accumulate_for_time(data, len);
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
        g_warning("Failed to unpack message len=%u", len);
        return;
    }

    switch (message->cmd_case) {
    case GPUTOP__MESSAGE__CMD_ERROR:
        log_add(0, message->error);
        break;
    case GPUTOP__MESSAGE__CMD_ACK:
        g_message("ack");
        break;
    case GPUTOP__MESSAGE__CMD_FEATURES:
        context.connection_state.features = message;
        register_platform_metrics(message->features->devinfo);
        maybe_open_i915_perf_stream();
        message = NULL; /* Save that structure for internal use */
        break;
    case GPUTOP__MESSAGE__CMD_LOG:
        for (size_t i = 0; i < message->log->n_entries; i++) {
            log_add(message->log->entries[i]->log_level,
                    message->log->entries[i]->log_message);
        }
        break;
    case GPUTOP__MESSAGE__CMD_CLOSE_NOTIFY:
        g_message("close-notify");
        break;
    case GPUTOP__MESSAGE__CMD_FILL_NOTIFY:
        g_message("fill-notify");
        break;
    case GPUTOP__MESSAGE__CMD_PROCESS_INFO:
        g_message("process-info");
        break;
    case GPUTOP__MESSAGE__CMD_CPU_STATS:
        if (cpu_stats_add(message))
            message = NULL;
        break;
    case GPUTOP__MESSAGE__CMD_TRACEPOINT_INFO:
        g_message("tracepoint-info");
        break;
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
    struct connection_state *state = &context.connection_state;
    const uint8_t *msg_type = (const uint8_t *) payload;
    const uint8_t *data = (const uint8_t *) payload + 8;
    size_t len = payload_len - 8;

    switch (*msg_type) {
    case 1:
        handle_perf_data(data, len);
        break;
    case 2:
        handle_protobuf_message(data, len);
        break;
    case 3: {
        const uint32_t *stream_id =
            (const uint32_t *) ((const uint8_t *) payload + 4);
        if (*stream_id == state->oa_stream_id)
            handle_i915_perf_data(data, len);
        else
            g_warning("discard wrong stream id=%i/%i",
                      *stream_id, state->oa_stream_id);
        break;
    }
    default:
        g_warning("unknown msg type=%hhi", *msg_type);
        break;
    }
}

static void
on_connection_closed(gputop_connection_t *conn,
                     const char *error,
                     void *user_data)
{
    struct connection_state *state = &context.connection_state;
    reset_connection_state();
    free(state->connection_error);
    state->connection_error = NULL;
    if (error) state->connection_error = strdup(error);
    context.connection_state.connection = NULL;
}

static void
on_connection_ready(gputop_connection_t *conn,
                    void *user_data)
{
    struct connection_state *state = &context.connection_state;

    request_features();
    open_cpu_stats_stream(state->cpu_stats_sampling_period_ms);
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
pretty_print_counter_value(const struct gputop_metric_set_counter *counter,
                           double value, char *buffer, size_t length)
{
    static const char *times[] = { "ns", "us", "ms", "s" };
    static const char *bytes[] = { "B", "KiB", "MiB", "GiB" };
    static const char *freqs[] = { "Hz", "KHz", "MHz", "GHz" };
    static const char *texels[] = { "texels", "K texels", "M texels", "G texels" };
    static const char *pixels[] = { "pixels", "K pixels", "M pixels", "G pixels" };
    static const char *cycles[] = { "cycles", "K cycles", "M cycles", "G cycles" };
    static const char *threads[] = { "threads", "K threads", "M threads", "G threads" };
    static const char **scales = NULL;

    switch (counter->units) {
    case GPUTOP_PERFQUERY_COUNTER_UNITS_BYTES:   scales = bytes; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_HZ:      scales = freqs; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_NS:
    case GPUTOP_PERFQUERY_COUNTER_UNITS_US:      scales = times; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_PIXELS:  scales = pixels; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_TEXELS:  scales = texels; break;
    case GPUTOP_PERFQUERY_COUNTER_UNITS_THREADS: scales = threads; break;
    }

    if (scales) {
        const double base = counter->units == GPUTOP_PERFQUERY_COUNTER_UNITS_BYTES ? 1024 : 100;
        const double multipliers[4] = { 0, base, base * base, base * base * base };

        if (counter->units == GPUTOP_PERFQUERY_COUNTER_UNITS_US)
            value *= 1000;

        int i = 0;
        while (value >= base && i < 3) {
            value /= base;
            i++;
        }
        snprintf(buffer, length, "%.3f %s", value, scales ? scales[i] : "");
    } else
        snprintf(buffer, length, "%f", value);
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
                                       sample->deltas);
        break;
    case GPUTOP_PERFQUERY_COUNTER_DATA_DOUBLE:
    case GPUTOP_PERFQUERY_COUNTER_DATA_FLOAT:
        if (counter->max_float)
            return counter->max_float(&state->devinfo,
                                      state->metric_set,
                                      sample->deltas);
        break;
    }

    return FLT_MAX;
}

static double
get_counter_max(struct connection_state *state,
                struct i915_perf_counter *counter)
{
    struct accumulated_samples *last_sample =
        list_last_entry(&state->graph,
                        struct accumulated_samples, link);
    counter->latest_max = MAX(read_counter_max(state, last_sample,
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
                                               sample->deltas);
        break;
    case GPUTOP_PERFQUERY_COUNTER_DATA_DOUBLE:
    case GPUTOP_PERFQUERY_COUNTER_DATA_FLOAT:
        return counter->oa_counter_read_float(&state->devinfo,
                                              state->metric_set,
                                              sample->deltas);
        break;
    }

    return 0.0f;
}

static float *
get_counter_samples(struct connection_state *state,
                    int max_graphs,
                    struct i915_perf_counter *counter)
{
    float *values = ensure_plot_accumulator(max_graphs);
    int i;

    for (i = 0; i < (max_graphs - state->n_graph); i++)
        values[i] = 0.0f;

    struct accumulated_samples *sample =
        list_first_entry(&state->graph,
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
    struct i915_perf_counter *c =
        (struct i915_perf_counter *) calloc(1, sizeof(*c));

    c->counter = counter;
    list_addtail(&c->link, &window->counters);
}

static void
remove_counter_i915_perf_window(struct i915_perf_counter *counter)
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
        list_last_entry(&state->graph,
                        struct accumulated_samples, link);

    ImGui::BeginChild("##block", ImVec2(0, 300));
    for (int c = 0; c < state->metric_set->n_counters; c++) {
        const struct gputop_metric_set_counter *counter =
            &state->metric_set->counters[c];
        if (!filter.PassFilter(counter->name)) continue;
        double value = read_counter_value(state, last_sample, counter);
        ImGui::ProgressBar(value / read_counter_max(state, last_sample, counter),
                           ImVec2(100, 0)); ImGui::SameLine();
        char svalue[100];
        pretty_print_counter_value(counter, value, svalue, sizeof(svalue));
        ImGui::Text(svalue); ImGui::SameLine();
        if (ImGui::Selectable(counter->name)) {
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
    if (state->n_graph < max_graphs) {
        ImGui::SameLine(); ImGui::Text("Loading:"); ImGui::SameLine();
        ImGui::ProgressBar((float) state->n_graph /  max_graphs);
    }

    ImGui::BeginChild("##block");
    ImGui::PushStyleColor(ImGuiCol_PlotLines, context.graph_color);
    list_for_each_entry_safe(struct i915_perf_counter, c, &window->counters, link) {
        ImGui::PushID(c);
        if (ImGui::Button("X")) { remove_counter_i915_perf_window(c); }
        ImGui::PopID();
        if (ImGui::IsItemHovered()) { ImGui::SetTooltip("Remove counter"); } ImGui::SameLine();
        ImGui::PlotLines("", get_counter_samples(state, max_graphs, c),
                         max_graphs, 0,
                         c->counter->name, 0, get_counter_max(state, c),
                         ImVec2(ImGui::GetContentRegionAvailWidth() - 10, 50.0f));
    }
    ImGui::PopStyleColor();
    ImGui::EndChild();
}

static void
cleanup_counters_i915_perf_window(struct i915_perf_window *window)
{
    list_for_each_entry_safe(struct i915_perf_counter, c,
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

    maybe_close_i915_perf_stream();
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

    maybe_open_i915_perf_stream();
}

/**/

static void
display_log_window(struct window *win)
{
    struct connection_state *state = &context.connection_state;

    ImGui::BeginChild(ImGui::GetID("##block"));
    for (int i = 0; i < state->n_messages; i++) {
        int idx = (state->start_message + i) % ARRAY_SIZE(state->messages);
        ImGui::Text(state->messages[idx].msg);
    }
    ImGui::EndChild();
}

static void
hide_log_window(struct window *win)
{
    /* NOP */
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
    window->destroy = hide_log_window;

    list_add(&window->link, &context.windows);
}

/**/

static float *
get_cpu_stats(struct connection_state *state, int max_cpu_stats, int cpu)
{
    float *values = ensure_plot_accumulator(max_cpu_stats);
    int i;

    for (i = 0; i < (max_cpu_stats - state->n_cpu_stats); i++)
        values[i] = 0.0f;

    struct cpu_stat *stat = list_first_entry(&state->cpu_stats,
                                             struct cpu_stat, link);
    for (; i < (max_cpu_stats - 1); i++) {
        struct cpu_stat *next = list_first_entry(&stat->link,
                                                 struct cpu_stat, link);
        assert(&next->link != &state->cpu_stats);

        Gputop__CpuStats *cpu_stat0 = stat->stat->cpu_stats->cpus[cpu];
        Gputop__CpuStats *cpu_stat1 = next->stat->cpu_stats->cpus[cpu];
        uint32_t total = ((cpu_stat1->user       - cpu_stat0->user) +
                          (cpu_stat1->nice       - cpu_stat0->nice) +
                          (cpu_stat1->system     - cpu_stat0->system) +
                          (cpu_stat1->idle       - cpu_stat0->idle) +
                          (cpu_stat1->iowait     - cpu_stat0->iowait) +
                          (cpu_stat1->irq        - cpu_stat0->irq) +
                          (cpu_stat1->steal      - cpu_stat0->steal) +
                          (cpu_stat1->guest      - cpu_stat0->guest) +
                          (cpu_stat1->guest_nice - cpu_stat0->guest_nice));
        if (total == 0)
            values[i] = 0.0f;
        else
            values[i] = 100.0f - 100.f * (float) (cpu_stat1->idle - cpu_stat0->idle) / total;

        stat = next;
    }

    return values;
}

static void
display_cpu_stats(void)
{
    struct connection_state *state = &context.connection_state;
    int n_cpus = state->features ? state->features->features->n_cpus : 1;
    int max_cpu_stats =
    (int) (state->cpu_stats_visible_timeline_s * 1000.0f) /
    state->cpu_stats_sampling_period_ms;

    ImGui::PushStyleColor(ImGuiCol_PlotLines, context.cpu_stats_color);

    for (int i = 0; i < n_cpus; i++) {
        char cpu_name[10];
        snprintf(cpu_name, sizeof(cpu_name), "CPU %i", i);
        ImGui::PlotLines("", get_cpu_stats(state, max_cpu_stats, i),
                         max_cpu_stats - 1, 0,
                         cpu_name, 0.0f, 100.0f,
                         ImVec2(ImGui::GetContentRegionAvailWidth(), 100.0f));
    }

    ImGui::PopStyleColor();
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

    ImGuiColorEditFlags cflags = (ImGuiColorEditFlags_NoAlpha |
                                  ImGuiColorEditFlags_NoInputs);
    ImGui::ColorEdit3("background", (float *)&context.clear_color, cflags); ImGui::SameLine();
    ImGui::ColorEdit3("graph color", (float *)&context.graph_color, cflags); ImGui::SameLine();
    ImGui::ColorEdit3("cpu stats color", (float *)&context.cpu_stats_color, cflags);

    ImGui::PushItemWidth(ImGui::GetContentRegionAvailWidth() / 4);
    if (ImGui::InputText("Address", state->host_address,
                         sizeof(state->host_address),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
        reconnect();
    } ImGui::SameLine();
    if (ImGui::InputInt("Port", &state->host_port, 1, 100,
                        ImGuiInputTextFlags_EnterReturnsTrue)) {
        reconnect();
    } ImGui::SameLine();
    ImGui::PopItemWidth();
    if (ImGui::Button("Connect")) reconnect();
    if (ImGui::Button("Logs")) { show_log_window(); } ImGui::SameLine();
    ImGui::Text("Status:"); ImGui::SameLine();
    bool is_connected = (state->connection &&
                         gputop_connection_connected(state->connection));
    ImColor color = is_connected ? ImColor(0.0f, 1.0f, 0.0f) : ImColor(0.9f, 0.0f, 0.0f);
    const char *connection_status = state->connection ?
        (is_connected ? "Connected" : "Connecting...") :
        (state->connection_error ? state->connection_error : "Not connected");
    ImGui::TextColored(color, connection_status);

    ImGui::Separator();
    int vcpu = state->cpu_stats_sampling_period_ms;
    if (ImGui::InputInt("CPU sampling period (ms)", &vcpu)) {
        vcpu = CLAMP(vcpu, 1, 1000);
        if (vcpu != state->cpu_stats_sampling_period_ms) { reopen_cpu_stats_stream(vcpu); }
    }
    ImGui::SliderFloat("CPU visible sampling (s)",
                       &state->cpu_stats_visible_timeline_s, 0.1f, 15.0f);

    int voa = state->oa_aggregation_period_ms;
    if (ImGui::InputInt("OA sampling period (ms)", &voa)) {
        voa = CLAMP(voa, 1, 1000);
        if (voa != state->oa_aggregation_period_ms) { maybe_reopen_i915_perf_stats_stream(voa); }
    }
    ImGui::SliderFloat("OA visible sampling (s)",
                       &state->oa_visible_timeline_s, 0.1f, 15.0f);

    if (state->features) {
        ImGui::Separator();
        ImGui::Text("CPU model: %s", state->features->features->cpu_model);
        ImGui::Text("Kernel release: %s", state->features->features->kernel_release);
        ImGui::Text("Kernel build: %s", state->features->features->kernel_build);
        const Gputop__DevInfo *devinfo = state->features->features->devinfo;
        ImGui::Text("GT name: %s (Gen %u, PCI 0x%x)",
                    devinfo->prettyname, devinfo->gen, devinfo->devid);
        ImGui::Text("%llu threads, %llu EUs, %llu slices, %llu subslices",
                    devinfo->eu_threads_count, devinfo->n_eus,
                    devinfo->n_eu_slices, devinfo->n_eu_sub_slices);
        ImGui::Text("GT frequency range %.1fMHz / %.1fMHz",
                    (double) devinfo->gt_min_freq / 1000000.0f,
                    (double) devinfo->gt_max_freq / 1000000.0f);

        ImGui::Text("Metric set: %s",
                    state->metric_set ? state->metric_set->name : "Not selected");
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
        ImGui::SetNextWindowSize(ImVec2(400, 400));
        if (ImGui::BeginPopup("metric counter picker")) {
            if (select_metric_set_from_counter(state, &state->metric_set))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        } ImGui::SameLine();
        if (ImGui::Button("New counter window"))
            new_i915_perf_window();
    }

    ImGui::Separator();
    display_cpu_stats();
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

static void
init_ui(void)
{
    list_inithead(&context.windows);
    list_inithead(&context.i915_perf_windows);
    context.clear_color = ImColor(114, 144, 154);
    context.graph_color = ImColor(37, 217, 50);
    context.cpu_stats_color = ImColor(255, 146, 58);

    list_inithead(&context.connection_state.cpu_stats);
    context.connection_state.n_cpu_stats = 0;
    context.connection_state.cpu_stats_visible_timeline_s = 3.0f;
    context.connection_state.cpu_stats_sampling_period_ms = 100;

    context.connection_state.oa_visible_timeline_s = 7.0f;
    context.connection_state.oa_aggregation_period_ms = 50;

    snprintf(context.connection_state.host_address,
             sizeof(context.connection_state.host_address), "localhost");
    context.connection_state.host_port = 7890;

    context.connection_state.metrics_map =
        _mesa_hash_table_create(NULL, _mesa_hash_string, _mesa_key_string_equal);

    reset_connection_state();
}

/**/
int
main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "GPUTop");
    g_signal_connect(window, "delete-event", G_CALLBACK(gtk_main_quit), NULL);
    gtk_window_resize(GTK_WINDOW(window), 1024, 768);

    GtkWidget *box = gtk_event_box_new();
    gtk_widget_set_can_focus(box, TRUE);
    gtk_container_add(GTK_CONTAINER(window), box);
    gtk_widget_show_all(window);

    CoglOnscreen *onscreen = ImGui_ImplGtk3Cogl_Init(box, repaint_window, NULL);

    init_ui();

    gtk_main();

    return EXIT_SUCCESS;
}
