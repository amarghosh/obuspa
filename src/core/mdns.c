
#ifdef ENABLE_MDNS

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#include "os_utils.h"
#include "usp_mem.h"
#include "mdns.h"


typedef struct {
    mdns_start_params_t start_params;
    AvahiSimplePoll *simple_poll;
    AvahiServer *server;
    bool running;
} mdns_t;

static int mdns_start_avahi_browse(mdns_t *mdns);

static mdns_t *g_mdns = NULL;

static void *mdns_thread(void *args);

int MDNS_init(void)
{
    g_mdns = USP_MALLOC(sizeof(*g_mdns));
    memset(g_mdns, 0, sizeof(*g_mdns));
    return 0;
}

int MDNS_destroy(void)
{
    if (g_mdns->running) {
        fprintf(stderr, "MDNS_destroy called without stopping");
        return -1;
    }

    USP_FREE(g_mdns);
    g_mdns = NULL;
    return 0;
}

int MDNS_start_listening(mdns_start_params_t *start_params)
{
    mdns_t *mdns = g_mdns;
    if (!mdns) {
        return -1;
    }

    if (mdns->running) {
        fprintf(stderr, "mdns already running with mtp=%d and endpoint=%d",
                mdns->start_params.mtp_type, mdns->start_params.end_point_type);
        return -1;
    }

    mdns->running = true;
    memcpy(&mdns->start_params, start_params, sizeof(*start_params));
    return OS_UTILS_CreateThread("avahi", mdns_thread, mdns);
}

int MDNS_stop(void)
{
    mdns_t *mdns = g_mdns;
    if (!mdns) {
        return -1;
    }

    if (!mdns->running) {
        return 0;
    }

    if (mdns->simple_poll) {
        avahi_simple_poll_quit(mdns->simple_poll);
        // TODO: use a semaphore to wait here until running becomes false so
        // that we can safely call destroy after a call to stop.
    }

    return 0;
}

static void *mdns_thread(void *args)
{
    mdns_t *mdns = args;
    mdns_start_avahi_browse(mdns);
    mdns->running = false;
    return NULL;
}


static void resolve_callback(
        AvahiSServiceResolver *r,
        AVAHI_GCC_UNUSED AvahiIfIndex interface,
        AVAHI_GCC_UNUSED AvahiProtocol protocol,
        AvahiResolverEvent event,
        const char *name,
        const char *type,
        const char *domain,
        const char *host_name,
        const AvahiAddress *address,
        uint16_t port,
        AvahiStringList *txt,
        AvahiLookupResultFlags flags,
        void* userdata)
{

    assert(r);
    mdns_t *mdns = userdata;

    /* Called whenever a service has been resolved successfully or timed out */

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n",
                    name, type, domain, avahi_strerror(avahi_server_errno(mdns->server)));
            break;

        case AVAHI_RESOLVER_FOUND: {
                char a[AVAHI_ADDRESS_STR_MAX], *t;

                fprintf(stderr, "(Resolver) Service '%s' of type '%s' in domain '%s' interface %d proto %d:\n", name, type, domain, interface, protocol);

                avahi_address_snprint(a, sizeof(a), address);
                t = avahi_string_list_to_string(txt);
                fprintf(stderr,
                        "\t%s:%u (%s)\n"
                        "\tTXT=%s\n"
                        "\tcookie is %u\n"
                        "\tis_local: %i\n"
                        "\twide_area: %i\n"
                        "\tmulticast: %i\n"
                        "\tcached: %i\n",
                        host_name, port, a,
                        t,
                        avahi_string_list_get_service_cookie(txt),
                        !!(flags & AVAHI_LOOKUP_RESULT_LOCAL),
                        !!(flags & AVAHI_LOOKUP_RESULT_WIDE_AREA),
                        !!(flags & AVAHI_LOOKUP_RESULT_MULTICAST),
                        !!(flags & AVAHI_LOOKUP_RESULT_CACHED));
                mdns->start_params.listener(host_name, a, port, mdns->start_params.userdata);
                avahi_free(t);
            }
    }

    avahi_s_service_resolver_free(r);
}

static void browse_callback(
        AvahiSServiceBrowser *b,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char *name,
        const char *type,
        const char *domain,
        AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
        void* userdata)
{
    mdns_t *mdns = userdata;
    assert(b);

    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */

    switch (event) {

        case AVAHI_BROWSER_FAILURE:

            fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_server_errno(mdns->server)));
            avahi_simple_poll_quit(mdns->simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
            fprintf(stderr, "(Browser) NEW: service '%s' of type '%s' in domain '%s'\n", name, type, domain);

            /* We ignore the returned resolver object. In the callback
               function we free it. If the server is terminated before
               the callback function is called the server will free
               the resolver for us. */

            if (!(avahi_s_service_resolver_new(mdns->server, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, mdns)))
                fprintf(stderr, "Failed to resolve service '%s': %s\n", name, avahi_strerror(avahi_server_errno(mdns->server)));

            break;

        case AVAHI_BROWSER_REMOVE:
            fprintf(stderr, "(Browser) REMOVE: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            break;

        case AVAHI_BROWSER_ALL_FOR_NOW:
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            fprintf(stderr, "(Browser) %s\n", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
            break;
    }
}

#define MAX_USP_SERVICE_NAME_LENGTH 32
static int generate_service_name(
    usp_mdns_mtp_t mtp_type,
    usp_mdns_end_point_t end_point,
    char *service_name)
{
    const char *end_point_str = end_point == kUspMdnsEndPoint_Agent ? "agt" : "ctr";
    const char *protocol = mtp_type == kUspMdnsMtp_Coap ? "udp" : "tcp";
    const char *mtp_str = NULL;
    switch (mtp_type) {
        case kUspMdnsMtp_Coap:
            mtp_str = "coap";
            break;
        case kUspMdnsMtp_Mqtt:
            mtp_str = "mqtt";
            break;
        case kUspMdnsMtp_Stomp:
            mtp_str = "stomp";
            break;
        case kUspMdnsMtp_WebSocket:
            mtp_str = "ws";
            break;
        default:
            return -1;
    }

    int len = snprintf(service_name, MAX_USP_SERVICE_NAME_LENGTH,
            "_usp-%s-%s._%s", end_point_str, mtp_str, protocol);
    if (len >= MAX_USP_SERVICE_NAME_LENGTH) {
        return -1;
    }

    return 0;
}

int mdns_start_avahi_browse(mdns_t *mdns)
{
    AvahiServerConfig config;
    AvahiSServiceBrowser *sb = NULL;
    char service_name[MAX_USP_SERVICE_NAME_LENGTH];
    int error;
    int ret = 1;

    ret = generate_service_name(mdns->start_params.mtp_type, mdns->start_params.end_point_type, service_name);
    if (ret != 0) {
        return -1;
    }

    printf("service: %s\n", service_name);


    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    if (!(mdns->simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    /* Do not publish any local records */
    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    /* Allocate a new server */
    mdns->server = avahi_server_new(avahi_simple_poll_get(mdns->simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    avahi_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    if (!mdns->server) {
        fprintf(stderr, "Failed to create server: %s\n", avahi_strerror(error));
        goto fail;
    }

    /* Create the service browser */
    if (!(sb = avahi_s_service_browser_new(
                    mdns->server,
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    service_name, NULL, 0,
                    browse_callback, mdns))) {
        fprintf(stderr, "Failed to create service browser: %s\n", avahi_strerror(avahi_server_errno(mdns->server)));
        goto fail;
    }

    /* Run the main loop */
    avahi_simple_poll_loop(mdns->simple_poll);

    ret = 0;

fail:

    /* Cleanup things */
    if (sb)
        avahi_s_service_browser_free(sb);

    if (mdns->server)
        avahi_server_free(mdns->server);

    if (mdns->simple_poll)
        avahi_simple_poll_free(mdns->simple_poll);

    mdns->server = NULL;
    mdns->simple_poll = NULL;

    return ret;
}

#endif

