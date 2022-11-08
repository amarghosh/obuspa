
#ifndef MDNS_H
#define MDNS_H

typedef enum {
    kUspMdnsMtp_Mqtt,
    kUspMdnsMtp_Coap,
    kUspMdnsMtp_Stomp,
    kUspMdnsMtp_WebSocket,
} usp_mdns_mtp_t;

typedef enum {
    kUspMdnsEndPoint_Agent,
    kUspMdnsEndPoint_Controller,
} usp_mdns_end_point_t;

typedef void (*usp_mdns_endpoint_listener_t)(
        const char *host_name, const char *ip, uint16_t port, void *userdata);

typedef struct {
    usp_mdns_mtp_t mtp_type;
    usp_mdns_end_point_t end_point_type;
    usp_mdns_endpoint_listener_t listener;
    void *userdata;
} mdns_start_params_t;

int MDNS_init(void);

int MDNS_destroy(void);

int MDNS_start_listening(mdns_start_params_t *start_params);

int MDNS_stop(void);

#endif // MDNS_H

