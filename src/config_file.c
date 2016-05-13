#include "config_file.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <arpa/inet.h>

#define NETWORK_ADDRESS_CONVERTED       1

bool                    config_file_parse_netif         (FILE *file, config_line_t *line, config_netif_t *netif);
bool                    config_file_parse_vlan          (FILE *file, config_line_t *line, config_vlan_t *vlan);
bool                    config_file_parse_gateway       (FILE *file, config_line_t *line, config_gateway_t *gateway);
bool                    config_file_parse_ptp           (FILE *file, config_line_t *line, config_ptp_t *ptp);
bool                    config_file_parse_ntp           (FILE *file, config_line_t *line, config_ntp_t *ntp);
bool                    config_file_parse_ntp_peer      (FILE *file, config_line_t *line, config_ntp_peer_t *peer, const char  *peername);
config_line_result_t    config_file_next_token          (config_line_t *line, char *token, const char *match);
void                    config_file_get_line_length     (config_line_t *line);
static bool             config_file_convert_to_integer  (config_line_t *line, const char *token, uint32_t *result);
static bool             config_file_convert_to_boolean  (config_line_t *line, const char *token, bool *result);
static bool             config_file_convert_to_mac(config_line_t *line, const char *token, mac_address_t *result);
static bool             config_file_convert_to_ipv4(config_line_t *line, const char *token, ipv4_address_t *result);

bool
config_file_parse(char *filename, config_t *config)
{
    FILE                   *file;
    config_line_t           line_stack;
    config_line_t          *line = &line_stack;
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;
    bool                    has_netif = false;
    uint32_t                netif_idx = 0;
    
    if ((file = fopen(filename, "r")) == NULL) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("can't open config-file \"%s\": %s", filename, strerror(errno)));
        return false;
    }
    
    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number = 1; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;
        
        config_file_get_line_length(line);
        
        /* parse first token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;      /**< it's just an empty line => skip this line */
        if (result == CONFIG_LINE_ERROR) return false;
        
        /* netif  */
        if (strcmp(token, "netif") == 0) {
            /* check overflow */
            if (netif_idx >= CONFIG_NETIF_MAX_SIZE) {
                LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: maximum 'netif' blocks reached at line %d:%d.", line->number, line->saved_position));
                return false;
            }

            /* parse second token: netif value */
            result = config_file_next_token(line, token, NULL);
            if (result == CONFIG_LINE_EOL)   goto netif_line_error;
            if (result == CONFIG_LINE_ERROR) return false;
            strncpy(config->netif[netif_idx].name, token, CONFIG_NETIF_NAME_MAX_SIZE);

            /* parse third token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto netif_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto netif_line_error;

            has_netif = true;
            if (!config_file_parse_netif(file, line, &(config->netif[netif_idx]))) {
                return false;
            }
            netif_idx++;
        } else {
            LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' at line %d:%d.", token, line->number, line->saved_position));
            return false;
        }
    }
    config->netif_size = netif_idx;
    
    if (!has_netif) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: no 'netif' block found at line %d:%d. must be specified!", line->number, line->saved_position));
        return false;
    }
    
    return true;
    
netif_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'netif' statement at line %d:%d", line->number, line->saved_position));
    return false;
    
}

bool
config_file_parse_netif(FILE *file, config_line_t *line, config_netif_t *netif)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;
    bool                    has_vlan = false;
    uint32_t                vlan_idx = 0;
    uint32_t                integer;
    
    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;

        config_file_get_line_length(line);

        /* parse first token: vlan */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;      /**< it's just an empty line => skip this line */
        if (result == CONFIG_LINE_ERROR) return false;

         /* end of netif block */
         if (strcmp(token, "}") == 0) {
             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto netif_body_error;

             netif->vlan_size = vlan_idx;

             /* leave netif body */
             return true;

         } else if (strcmp(token, "vlan") == 0) {

             /* check overflow */
             if (vlan_idx >= CONFIG_VLAN_MAX_SIZE) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: maximum 'vlan' blocks reached in 'netif' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }

            /* parse second token: vlan value */
            result = config_file_next_token(line, token, NULL);
            if (result == CONFIG_LINE_EOL)   goto vlan_line_error;
            if (result == CONFIG_LINE_ERROR) return false;
            if (!config_file_convert_to_integer(line, token, &integer)) {
                return false;
            }
            netif->vlan[vlan_idx].vid = integer;

            /* parse third token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto vlan_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto vlan_line_error;

            has_vlan = true;
            if (!config_file_parse_vlan(file, line, &(netif->vlan[vlan_idx]))) {
                return false;
            }
            vlan_idx++;
         } else {
             LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' in 'netif' block at line %d:%d.", token, line->number, line->saved_position));
             return false;
         }

         /* are there still other tokens left? */
         result = config_file_next_token(line, token, NULL);
         if (result != CONFIG_LINE_EOL)   goto netif_body_error;
    }

    if (!has_vlan) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: no 'vlan' block in 'netif' block found at line %d:%d. must be specified!", line->number, line->saved_position));
        return false;
    }
    
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'netif' block at line %d:%d. No closing bracket!", line->number, line->saved_position));
    return false;

netif_body_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement in 'netif' block at line %d:%d", line->number, line->saved_position));
    return false;

vlan_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'vlan' statement in 'netif' block at line %d:%d", line->number, line->saved_position));
    return false;

}

bool
config_file_parse_vlan(FILE *file, config_line_t *line, config_vlan_t *vlan)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;

    vlan->gateway_configured = false;
    vlan->ptp_configured     = false;
    vlan->ntp_configured     = false;
    
    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;
        
        config_file_get_line_length(line);
        
        /* parse token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;
        if (result == CONFIG_LINE_ERROR) return false;
        
        /* evaluate token */
        
         /* end of vlan block */
         if (strcmp(token, "}") == 0) {
             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto vlan_body_error;

             /* leave vlan body */
             return true;

         /* gateway */
         } else if (strcmp(token, "gateway") == 0) {

             /* gateway already configured? */
             if (vlan->gateway_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: only one 'gateway' block allowed in 'vlan' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }
             vlan->gateway_configured = true;

            /* parse second token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto gateway_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto gateway_line_error;

            if (!config_file_parse_gateway(file, line, &(vlan->gateway))) {
                return false;
            }

         /* ptp */
         } else if (strcmp(token, "ptp") == 0) {

             /* ptp already configured? */
             if (vlan->ptp_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: only one 'ptp' block allowed in 'vlan' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }
             vlan->ptp_configured = true;

            /* parse second token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto ptp_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto ptp_line_error;

            if (!config_file_parse_ptp(file, line, &(vlan->ptp))) {
                return false;
            }


         /* ntp */
         } else if (strcmp(token, "ntp") == 0) {

             /* ntp already configured? */
             if (vlan->ntp_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: only one 'ntp' block allowed in 'vlan' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }
             vlan->ntp_configured = true;

            /* parse second token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto ntp_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto ntp_line_error;

            if (!config_file_parse_ntp(file, line, &(vlan->ntp))) {
                return false;
            }
         } else {
             LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' in 'vlan' block at line %d:%d.", token, line->number, line->saved_position));
             return false;
         }

         /* are there still other tokens left? */
         result = config_file_next_token(line, token, NULL);
         if (result != CONFIG_LINE_EOL)   goto vlan_body_error;
    }

    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'vlan' block at line %d:%d. No closing bracket!", line->number, line->saved_position));
    return false;

vlan_body_error:
     LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement in 'vlan' block at line %d:%d", line->number, line->saved_position));
     return false;

gateway_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'gateway' statement in 'vlan' block at line %d:%d", line->number, line->saved_position));
    return false;

ptp_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'ptp' statement in 'vlan' block at line %d:%d", line->number, line->saved_position));
    return false;

ntp_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'ntp' statement in 'vlan' block at line %d:%d", line->number, line->saved_position));
    return false;

}

bool
config_file_parse_gateway(FILE *file, config_line_t *line, config_gateway_t *gateway)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;
    bool                    mac_configured = false;
    bool                    ipv4_configured = false;

    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;

        config_file_get_line_length(line);

        /* parse token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;
        if (result == CONFIG_LINE_ERROR) return false;

        /* evaluate token */

         /* end of gateway block */
         if (strcmp(token, "}") == 0) {
             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto gateway_body_error;

             /* leave gateway body */
             return true;

         /* mac */
         } else if (strcmp(token, "mac") == 0) {
             /* mac already configured? */
             if (mac_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: multiple 'mac' statements in 'gateway' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }
             mac_configured = true;

             result = config_file_next_token(line, token, NULL);
             if (result == CONFIG_LINE_EOL)   goto gateway_body_error;
             if (result == CONFIG_LINE_ERROR) return false;

             if (!config_file_convert_to_mac(line, token, &(gateway->mac_address))) {
                 return false;
             }

         /* ipv4 */
         } else if (strcmp(token, "ipv4") == 0) {
             /* ipv4 already configured? */
             if (ipv4_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: multiple 'ipv4' statements in 'gateway' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }
             ipv4_configured = true;

             result = config_file_next_token(line, token, NULL);
             if (result == CONFIG_LINE_EOL)   goto gateway_body_error;
             if (result == CONFIG_LINE_ERROR) return false;

             if (!config_file_convert_to_ipv4(line, token, &(gateway->ipv4_address))) {
                 return false;
             }
         } else {
             LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' in 'gateway' block at line %d:%d.", token, line->number, line->saved_position));
             return false;
         }

         /* are there still other tokens left? */
         result = config_file_next_token(line, token, NULL);
         if (result != CONFIG_LINE_EOL)   goto gateway_body_error;
    }

    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'gateway' block at line %d:%d. No closing bracket!", line->number, line->saved_position));
    return false;

gateway_body_error:
     LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement in 'gateway' block at line %d:%d", line->number, line->saved_position));
     return false;

}

bool
config_file_parse_ptp(FILE *file, config_line_t *line, config_ptp_t *ptp)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;

    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;

        config_file_get_line_length(line);

        /* parse token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;
        if (result == CONFIG_LINE_ERROR) return false;

        /* evaluate token */

        // /* end of subnet */
        // if (strcmp(token, "}") == 0) {
            // /* are there still other tokens left? */
            // result = config_file_next_token(line, token, NULL);
            // if (result != CONFIG_LINE_EOL)   goto subnet_body_error;
            //
            // /* check whether all statements are loaded */
            // if (!hasRange || !hasBroadcast || !hasLeaseTime) {
                // LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: 'subnet' block must include 'range', 'broadcast' and 'lease-time' statements"));
                // return false;
            // }
            //
            // /* leave subnet body */
            // return true;
            //
        // /* force options (boolean) */
        // } else if (strcmp(token, "force-options") == 0) {
            // result = config_file_next_token(line, token, NULL);
            // if (result == CONFIG_LINE_EOL)   goto subnet_body_error;
            // if (result == CONFIG_LINE_ERROR) return false;
            //
            // if (!config_file_convert_to_boolean(line, token, &(config->forceOptions))) {
                // return false;
            // }
            //
        // /* ignore xid compare (boolean) */
        // } else if (strcmp(token, "ignore-xid-compare") == 0) {
            // result = config_file_next_token(line, token, NULL);
            // if (result == CONFIG_LINE_EOL)   goto subnet_body_error;
            // if (result == CONFIG_LINE_ERROR) return false;
            //
            // if (!config_file_convert_to_boolean(line, token, &(config->ignoreXidCompare))) {
                // return false;
            // }
            //
        // } else {
            // LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' at line %d:%d.", token, line->number, line->savedPosition));
            // return false;
        // }
        //
        // /* parse token: ';' */
        // result = config_file_next_token(line, token, ";");
        // if (result == CONFIG_LINE_EOL)   goto subnet_body_error;
        // if (result == CONFIG_LINE_ERROR) return false;
        //
        // /* are there still other tokens left? */
        // result = config_file_next_token(line, token, NULL);
        // if (result != CONFIG_LINE_EOL)   goto bracket_error;
    }


    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'subnet' statement at line %d:%d. No closing bracket!", line->number, line->saved_position));
    return false;

// subnet_body_error:
    // LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement at line %d:%d", line->number, line->savedPosition));
    // return false;
    //
// bracket_error:
    // LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token after end of semicolon at line %d:%d", line->number, line->savedPosition));
    // return false;
}

bool
config_file_parse_ntp(FILE *file, config_line_t *line, config_ntp_t *ntp)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;
    uint32_t                client_idx = 0;
    bool                    server_configured = false;

    ntp->adva_tlv = false;

    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;

        config_file_get_line_length(line);

        /* parse token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;
        if (result == CONFIG_LINE_ERROR) return false;

        /* evaluate token */

         /* end of subnet */
         if (strcmp(token, "}") == 0) {
             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto ntp_body_error;

             ntp->client_size = client_idx;

             /* leave subnet body */
             return true;

         /* server */
         } else if (strcmp(token, "server") == 0) {
             /* server already configured */
             if (server_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: multiple 'server' statements in 'ntp' block at line %d:%d.", line->number, line->saved_position));
                 return false;
             }

            /* parse second token: '{' */
            result = config_file_next_token(line, token, "{");
            if (result == CONFIG_LINE_EOL)   goto ntp_server_line_error;
            if (result == CONFIG_LINE_ERROR) return false;

            /* are there still other tokens left? */
            result = config_file_next_token(line, token, NULL);
            if (result != CONFIG_LINE_EOL)   goto ntp_client_line_error;

            if (!config_file_parse_ntp_peer(file, line, &(ntp->server), "server")) {
                return false;
            }
            server_configured = true;

         /* adva-tlv (boolean) */
         } else if (strcmp(token, "adva-tlv") == 0) {
             result = config_file_next_token(line, token, NULL);
             if (result == CONFIG_LINE_EOL)   goto ntp_body_error;
             if (result == CONFIG_LINE_ERROR) return false;

             if (!config_file_convert_to_boolean(line, token, &(ntp->adva_tlv))) {
                 return false;
             }

         /* client */
          } else if (strcmp(token, "client") == 0) {

              /* check overflow */
              if (client_idx >= CONFIG_NTP_CLIENT_MAX_SIZE) {
                  LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: maximum 'client' blocks reached in 'ntp' block at line %d:%d.", line->number, line->saved_position));
                  return false;
              }

             /* parse second token: '{' */
             result = config_file_next_token(line, token, "{");
             if (result == CONFIG_LINE_EOL)   goto ntp_client_line_error;
             if (result == CONFIG_LINE_ERROR) return false;

             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto ntp_client_line_error;

             if (!config_file_parse_ntp_peer(file, line, &(ntp->client[client_idx]), "client")) {
                 return false;
             }
             client_idx++;

         } else {
             LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' at line %d:%d.", token, line->number, line->saved_position));
             return false;
         }

         /* are there still other tokens left? */
         result = config_file_next_token(line, token, NULL);
         if (result != CONFIG_LINE_EOL)   goto ntp_body_error;
    }
    
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'ntp' block at line %d:%d. No closing bracket!", line->number, line->saved_position));
    return false;

ntp_body_error:
     LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement in 'ntp' block at line %d:%d", line->number, line->saved_position));
     return false;

ntp_server_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'server' statement in 'ntp' block at line %d:%d", line->number, line->saved_position));
    return false;


ntp_client_line_error:
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished 'client' statement in 'ntp' block at line %d:%d", line->number, line->saved_position));
    return false;
}

bool
config_file_parse_ntp_peer(FILE *file, config_line_t *line, config_ntp_peer_t *peer, const char  *peername)
{
    char                    token[CONFIG_FILE_LINE_SIZE];
    config_line_result_t    result;
    bool                    mac_configured = false;
    bool                    ipv4_configured = false;

    /* get line by line (max. size = LINE_SIZE, oversized lines are not handled proper!) */
    for (line->number++; fgets((char *) line->text, sizeof(line->text), file) != NULL; line->number++) {
        line->position = 0;

        config_file_get_line_length(line);

        /* parse token */
        result = config_file_next_token(line, token, NULL);
        if (result == CONFIG_LINE_EOL)   continue;
        if (result == CONFIG_LINE_ERROR) return false;

        /* evaluate token */

         /* end of ntp peer block */
         if (strcmp(token, "}") == 0) {
             /* are there still other tokens left? */
             result = config_file_next_token(line, token, NULL);
             if (result != CONFIG_LINE_EOL)   goto ntp_peer_body_error;

             /* leave ntp peer body */
             return true;

         /* mac */
         } else if (strcmp(token, "mac") == 0) {
             /* mac already configured? */
             if (mac_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: multiple 'mac' statements in '%s' block at line %d:%d.", peername, line->number, line->saved_position));
                 return false;
             }
             mac_configured = true;

             result = config_file_next_token(line, token, NULL);
             if (result == CONFIG_LINE_EOL)   goto ntp_peer_body_error;
             if (result == CONFIG_LINE_ERROR) return false;

             if (!config_file_convert_to_mac(line, token, &(peer->mac_address))) {
                 return false;
             }

         /* ipv4 */
         } else if (strcmp(token, "ipv4") == 0) {
             /* ipv4 already configured? */
             if (ipv4_configured) {
                 LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: multiple 'ipv4' statements in '%s' block at line %d:%d.", peername, line->number, line->saved_position));
                 return false;
             }
             ipv4_configured = true;

             result = config_file_next_token(line, token, NULL);
             if (result == CONFIG_LINE_EOL)   goto ntp_peer_body_error;
             if (result == CONFIG_LINE_ERROR) return false;

             if (!config_file_convert_to_ipv4(line, token, &(peer->ipv4_address))) {
                 return false;
             }
         } else {
             LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' in '%s' block at line %d:%d.", token, peername, line->number, line->saved_position));
             return false;
         }

         /* are there still other tokens left? */
         result = config_file_next_token(line, token, NULL);
         if (result != CONFIG_LINE_EOL)   goto ntp_peer_body_error;
    }

    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished '%s' block at line %d:%d. No closing bracket!", peername, line->number, line->saved_position));
    return false;

    ntp_peer_body_error:
     LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unfinished statement in '%s' block at line %d:%d", peername, line->number, line->saved_position));
     return false;

}

config_line_result_t
config_file_next_token(config_line_t *line, char *token, const char *match)
{
    uint32_t token_position = 0;
    
    /* absorb leading spaces */
    for (; line->text[line->position] == ' '; line->position++);
    
    line->saved_position = line->position;
    
    /* reach end-of-line (eol) if the line has too much spaces */
    if (line->position >= line->length) {
        return CONFIG_LINE_EOL;
    }
    
    /* comment, ignor rest of line */
    if (line->text[line->position] == '#') {
        return CONFIG_LINE_EOL;
    }
    
    /* parse token */
    token[token_position++] = line->text[line->position++];
    /* parse until end-of-line or space or semicolon */
    for (;
         line->position < line->length && line->text[line->position] != ' ' && line->text[line->position] != ';';
         line->position++, token_position++) {
        
        token[token_position] = line->text[line->position];
    }
    token[token_position] = '\0';
    
    if (match != NULL) {
        if (strcmp(token, match) != 0) {
            LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: unknow token '%s' at line %d:%d. should be '%s'", token, line->number, line->saved_position, match));
            return CONFIG_LINE_ERROR;
        }
    }
    
    return CONFIG_LINE_TOKEN;
}

void
config_file_get_line_length(config_line_t *line)
{
    uint32_t    line_postition;
    
    /* count characters until newline (\n) or EOF (\0) is reached */
    for (line_postition = 0; line->text[line_postition] != '\n' && line->text[line_postition] != '\r' && line->text[line_postition] != '\0'; line_postition++);
    
    line->length = line_postition;
}

static bool
config_file_convert_to_integer(config_line_t *line, const char *token, uint32_t *result)
{
    char *end;
    const long longValue = strtol(token, &end, 10 /* = decimal conversion */ );
    
    if (end == token) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' is not a decimal number at line %d:%d.", token, line->number, line->saved_position));
        return false;
    } else if (*end != '\0') {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' has extra characters at line %d:%d.", token, line->number, line->saved_position));
        return false;
    } else if (longValue > UINT32_MAX) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' is out-of-range at line %d:%d.", token, line->number, line->saved_position));
        return false;
    }
    
    *result = (uint32_t) longValue;
    
    return true;
}

static bool
config_file_convert_to_boolean(config_line_t *line, const char *token, bool *result)
{
    if (strcasecmp(token, "true") == 0) {
        *result = true;
        return true;
        
    } else if (strcasecmp(token, "false") == 0) {
        *result = false;
        return true;
    }
    
    LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' is not a boolen value at line %d:%d.", token, line->number, line->saved_position));
    return false;
}

static bool
config_file_convert_to_mac(config_line_t *line, const char *token, mac_address_t *result)
{
    if (!mac_address_convert_from_string(result, (const uint8_t *) token)) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' is not a MAC address at line %d:%d.", token, line->number, line->saved_position));
        return false;
    }

    return true;
}

static bool
config_file_convert_to_ipv4(config_line_t *line, const char *token, ipv4_address_t *result)
{
    if (!ipv4_address_convert_from_string(result, (const uint8_t *) token)) {
        LOG_PRINTLN(LOG_CONFIG_FILE, LOG_ERROR, ("parse config-file: token '%s' is not an IP4 address at line %d:%d.", token, line->number, line->saved_position));
        return false;
    }

    return true;
}
