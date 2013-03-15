//
//  main.c
//  eyefiserver
//
//  Created by Michael Russell on 28/02/13.
//  Copyright (c) 2013 Michael Russell. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "md5.h"
#include "hexString.h"

#define PAGE "<html><head><title>Eye-Fi Server</title></head><body>Eye-Fi Server</body></html>"

#define EYEFI_MAC_ADDRESS "00185649671f"
#define EYEFI_UPLOAD_KEY "8c327dde9971132c457a8f15d8333d44"
#define EYEFI_UPLOAD_PATH "/Users/mike/eye-fi/"

#define EYEFI_API_URL "/api/soap/eyefilm/v1"
#define EYEFI_UPLOAD_URL "/api/soap/eyefilm/v1/upload"

#define SOAP_ENVELOPE_KEY "SOAPENVELOPE"
#define FILENAME_KEY "FILENAME"

#define SOAP_ACTION_HEADER "SOAPAction"
#define ACTION_START_SESSION "\"urn:StartSession\""
#define ACTION_GET_PHOTO_STATUS "\"urn:GetPhotoStatus\""
#define ACTION_MARK_LAST_PHOTO_IN_ROLL "\"urn:MarkLastPhotoInRoll\""
#define ACTION_UPLOAD_PHOTO "\"urn:UplaodPhoto\""

#define DUMP_SOAP 0

struct Request {
    char *soap_method;
    struct MHD_PostProcessor *pp;
    char *data;
    size_t data_length;
    int content_length;
    char filename[255];
    char tmp_file[255];
    FILE *main_file;
};

struct Response {
    char *data;
    size_t data_length;
};

static void free_request(struct Request *request) {
    if (request->soap_method != NULL) {
        free(request->soap_method);
    }
    if (request->data != NULL) {
        free(request->data);
    }
    if (request->main_file != NULL) {
        fclose(request->main_file);
    }
    free(request);
}

static void free_response(struct Response *response) {
    if (response->data != NULL) {
        free(response->data);
    }
    free(response);
}

static xmlNodePtr find_xml_node(xmlNodePtr node, const char *search) {
    xmlNode *cur_node = NULL;
    
    for (cur_node = node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, BAD_CAST search) == 0) {
                return cur_node;
            }
        }
        
        xmlNodePtr sub_search = find_xml_node(cur_node->children, search);
        if (sub_search) {
            return sub_search;
        }
    }
    
    return NULL;
}

static char *get_xml_node_value(xmlNodePtr node, const char *search) {
    xmlNodePtr curr = NULL;
    
    curr = find_xml_node(node, search);
    if (curr == NULL) {
        return NULL;
    }
    char *result = (char *)xmlNodeGetContent(curr->children);
    
    return result;
}

static xmlNodePtr add_xml_child_node(xmlNodePtr parent, const char *name, const char *value) {
    xmlNodePtr node = xmlNewNode(NULL, BAD_CAST name);
    xmlAddChild(node, xmlNewText(BAD_CAST value));
    xmlAddChild(parent, node);
    return node;
}

static void xml_doc_to_bytes(xmlDocPtr doc, char **data, size_t *size) {
    xmlChar *raw_xml;
    int xml_size;
    xmlDocDumpMemory(doc, &raw_xml, &xml_size);
    
    *data = (char *)malloc(xml_size);
    memcpy(*data, raw_xml, xml_size);
    *size = xml_size;
    
    xmlFree(raw_xml);
}

static struct Response *process_start_session(struct Request *request) {
    xmlDocPtr request_doc = xmlReadMemory(request->data, (int)request->data_length, "noname.xml", NULL, 0);
    
    if (request_doc == NULL) {
        fprintf(stderr, "Failed to parse document\n");
        return NULL;
    }
    
    xmlNodePtr root_element = xmlDocGetRootElement(request_doc);
    xmlNodePtr session_node = find_xml_node(root_element, "StartSession")->children;
    
    char *mac_address = get_xml_node_value(session_node, "macaddress");
    char *cnonce = get_xml_node_value(session_node, "cnonce");
    char *transfer_mode = get_xml_node_value(session_node, "transfermode");
    char *transfer_mode_timestamp = get_xml_node_value(session_node, "transfermodetimestamp");
        
    size_t raw_length = strlen(mac_address) + strlen(cnonce) + strlen(EYEFI_UPLOAD_KEY) + 1;
    char *raw_credential = (char *)malloc(raw_length);
    snprintf(raw_credential, raw_length, "%s%s%s", mac_address, cnonce, EYEFI_UPLOAD_KEY);
    
    printf("credential string before md5 %s\n", raw_credential);
    
    unsigned char *binary_credential = hexStringToBytes(raw_credential);
    int binary_length = (int)(strlen(raw_credential) / 2);
    
    unsigned char digest[16];

    MD5_CTX md5;
    
    MD5_Init(&md5);
    MD5_Update(&md5, binary_credential, binary_length);
    MD5_Final(digest, &md5);
    
    free(raw_credential);
    free(binary_credential);
    
    char *credential_string = bytesToHexString(digest, 16);
    
    printf("md5 credential %s length %zd\n", credential_string, strlen(credential_string));
    
    xmlDocPtr response_doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
   
    xmlNodePtr root_node = xmlNewNode(NULL, BAD_CAST "Envelope");
    xmlNsPtr soap_ns = xmlNewNs(root_node, BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/", BAD_CAST "SOAP-ENV");
    
    xmlDocSetRootElement(response_doc, root_node);
    xmlNodePtr body = xmlNewNode(soap_ns, BAD_CAST "Body");

    xmlAddChild(root_node, body);
    
    xmlNodePtr response = xmlNewNode(NULL, BAD_CAST "StartSessionResponse");
    xmlNewNs(response, BAD_CAST "http://localhost/api/soap/eyefilm", BAD_CAST "ns1");
    
    xmlAddChild(body, response);
    
    add_xml_child_node(response, "credential", credential_string);
    add_xml_child_node(response, "snonce", cnonce);
    add_xml_child_node(response, "transfermode", transfer_mode);
    add_xml_child_node(response, "transfermodetimestamp", transfer_mode_timestamp);
    add_xml_child_node(response, "upsyncallowed", "false");
  
    // xmlSaveFormatFileEnc("/Users/mike/test.xml", response_doc, "UTF-8", 1);
    
    struct Response *response_data = (struct Response*)calloc(1, sizeof(struct Response));
    xml_doc_to_bytes(response_doc, &response_data->data, &response_data->data_length);
    xmlFreeDoc(response_doc);
    
    xmlFreeDoc(request_doc);

    return response_data;
}

static struct Response *process_mark_last_photo_in_rool(struct Request *request) {
    xmlDocPtr request_doc = xmlReadMemory(request->data, (int)request->data_length, "noname.xml", NULL, 0);
    
    if (request_doc == NULL) {
        fprintf(stderr, "Failed to parse document\n");
        return NULL;
    }
    
    xmlNodePtr root_element = xmlDocGetRootElement(request_doc);
    xmlNodePtr photo_status_node = find_xml_node(root_element, "MarkLastPhotoInRoll")->children;
    char *macaddress = get_xml_node_value(photo_status_node, "macaddress");
    char *merge_delta = get_xml_node_value(photo_status_node, "mergedelta");
    
    xmlDocPtr response_doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
    
    xmlNodePtr root_node = xmlNewNode(NULL, BAD_CAST "Envelope");
    xmlNsPtr soap_ns = xmlNewNs(root_node, BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/", BAD_CAST "SOAP-ENV");
    
    xmlDocSetRootElement(response_doc, root_node);
    xmlNodePtr body = xmlNewNode(soap_ns, BAD_CAST "Body");
    
    xmlAddChild(root_node, body);
    
    xmlNodePtr response = xmlNewNode(NULL, BAD_CAST "StartSessionResponse");
    xmlNewNs(response, BAD_CAST "http://localhost/api/soap/eyefilm", BAD_CAST "ns1");
    
    xmlAddChild(body, response);
    
    // xmlSaveFormatFileEnc("/Users/mike/test.xml", response_doc, "UTF-8", 1);
    
    struct Response *response_data = (struct Response*)calloc(1, sizeof(struct Response));
    xml_doc_to_bytes(response_doc, &response_data->data, &response_data->data_length);
    xmlFreeDoc(response_doc);
    
    xmlFreeDoc(request_doc);
    
    return response_data;
}

static struct Response *process_get_photo_status(struct Request *request) {
    xmlDocPtr request_doc = xmlReadMemory(request->data, (int)request->data_length, "noname.xml", NULL, 0);
    
    if (request_doc == NULL) {
        fprintf(stderr, "Failed to parse document\n");
        return NULL;
    }
    
    xmlNodePtr root_element = xmlDocGetRootElement(request_doc);
    xmlNodePtr photo_status_node = find_xml_node(root_element, "GetPhotoStatus")->children;
    const char *credential = get_xml_node_value(photo_status_node, "credential");
    const char *macaddress = get_xml_node_value(photo_status_node, "macaddress");
    const char *filename = get_xml_node_value(photo_status_node, "filename");
    const char *filesize = get_xml_node_value(photo_status_node, "filesize");
    const char *filesignature = get_xml_node_value(photo_status_node, "filesignature");
    const char *flags = get_xml_node_value(photo_status_node, "flags");

    xmlDocPtr response_doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
    
    xmlNodePtr root_node = xmlNewNode(NULL, BAD_CAST "Envelope");
    xmlNsPtr soap_ns = xmlNewNs(root_node, BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/", BAD_CAST "SOAP-ENV");
    
    xmlDocSetRootElement(response_doc, root_node);
    xmlNodePtr body = xmlNewNode(soap_ns, BAD_CAST "Body");
    
    xmlAddChild(root_node, body);
    
    xmlNodePtr response = xmlNewNode(NULL, BAD_CAST "GetPhotoStatusResponse");
    xmlNewNs(response, BAD_CAST "http://localhost/api/soap/eyefilm", BAD_CAST "ns1");
    
    xmlAddChild(body, response);
    
    static int fileid = 0;
    fileid++;
    char str[32];
    snprintf(str, 32, "%d", fileid);
    
    add_xml_child_node(response, "fileid", str);
    add_xml_child_node(response, "offset", "0");
    
    // xmlSaveFormatFileEnc("/Users/mike/test.xml", response_doc, "UTF-8", 1);
    
    struct Response *response_data = (struct Response*)calloc(1, sizeof(struct Response));
    xml_doc_to_bytes(response_doc, &response_data->data, &response_data->data_length); 
    xmlFreeDoc(response_doc);
    
    xmlFreeDoc(request_doc);
    
    return response_data;
}

static struct Response *process_upload_photo(struct Request *request) {
    xmlDocPtr request_doc = xmlReadMemory(request->data, (int)request->data_length, "noname.xml", NULL, 0);
    
    if (request_doc == NULL) {
        fprintf(stderr, "Failed to parse document\n");
        return NULL;
    }
    
    xmlNodePtr root_element = xmlDocGetRootElement(request_doc);
    xmlNodePtr data_node = find_xml_node(root_element, "UploadPhoto")->children;
    const char *file_id = get_xml_node_value(data_node, "fileid");
    const char *macaddress = get_xml_node_value(data_node, "macaddress");
    const char *filename = get_xml_node_value(data_node, "filename");
    const char *filesize = get_xml_node_value(data_node, "filesize");
    const char *file_signature = get_xml_node_value(data_node, "filesignature");
    const char *encryption = get_xml_node_value(data_node, "encryption");
    const char *flags = get_xml_node_value(data_node, "flags");
    
    if (request->main_file) {
        fclose(request->main_file);
        request->main_file = NULL;
    }
    
    char cmd[255];
    snprintf(cmd, 255, "gnutar -xf %s -C %s", request->tmp_file, EYEFI_UPLOAD_PATH);
    printf("calling system %s\n", cmd);
    if (system(cmd) == 0) {
        printf("succeeded\n");
    } else {
        printf("failed\n");
        return NULL;
    }
    
    printf("deleting temp file %s\n", request->tmp_file);
    unlink(request->tmp_file);
    
    xmlDocPtr response_doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
    
    xmlNodePtr root_node = xmlNewNode(NULL, BAD_CAST "Envelope");
    xmlNsPtr soap_ns = xmlNewNs(root_node, BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/", BAD_CAST "SOAP-ENV");
    
    xmlDocSetRootElement(response_doc, root_node);
    xmlNodePtr body = xmlNewNode(soap_ns, BAD_CAST "Body");
    
    xmlAddChild(root_node, body);
    
    xmlNodePtr response = xmlNewNode(NULL, BAD_CAST "UploadPhotoResponse");
    xmlNewNs(response, BAD_CAST "http://localhost/api/soap/eyefilm", BAD_CAST "ns1");
    
    xmlAddChild(body, response);
    
    add_xml_child_node(response, "success", "true");
    
    struct Response *response_data = (struct Response*)calloc(1, sizeof(struct Response));
    xml_doc_to_bytes(response_doc, &response_data->data, &response_data->data_length);
    xmlFreeDoc(response_doc);
 
    xmlFreeDoc(request_doc);

    return response_data;
}
    
static int post_iterator (void *cls,
               enum MHD_ValueKind kind,
               const char *key,
               const char *filename,
               const char *content_type,
               const char *transfer_encoding,
               const char *data, uint64_t off, size_t size)
{
    struct Request *request = (struct Request *)cls;
    
    if (strcmp(SOAP_ENVELOPE_KEY, key) == 0) {
        if (request->data == NULL) {
            request->data = (char *)malloc(4096);
        }
        memcpy(request->data + request->data_length, data, size);
        request->data_length+= size;
    }
    
    if (strcmp(FILENAME_KEY, key) == 0) {
        if (request->main_file == NULL) {
            strncpy(request->filename, filename, 255);
            snprintf(request->tmp_file, 255, "%s%s", EYEFI_UPLOAD_PATH, filename);
            printf("recieving file %s to %s\n", filename, request->tmp_file);
            request->main_file = fopen(request->tmp_file, "wb");
        }
        fwrite(data, 1, size, request->main_file);
    }

  /*  printf("key %s\n", key);
    printf("filename %s\n", filename);
    printf("content_type %s\n", content_type);
    printf("size %zd\n", size);
   */
    return MHD_YES;
}

static int header_iterator(void *cls,
        enum MHD_ValueKind kind,
        const char *key, const char *value) {
    
    struct Request *request = (struct Request *)cls;
    
    if (strcmp(key, SOAP_ACTION_HEADER) == 0) {
        request->soap_method = (char *)malloc(strlen(value) + 1);
        strcpy(request->soap_method, value);
    }
 
    return MHD_YES;
}

static int process_request(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr) {
    struct MHD_Response *response;
    int ret;
        
    struct Request *request;
    request = (struct Request *)*ptr;
    
    if (request == NULL) {
        printf("New Request: %s %s\n", method, url);

        request = (struct Request*)calloc(1, sizeof(struct Request));
        *ptr = request;

        MHD_get_connection_values(connection, MHD_HEADER_KIND, &header_iterator, request);
        
        if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
            const char *clen = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
            printf("Request content length %s\n", clen);
            request->content_length = atoi(clen);
            
            const char *encoding = MHD_lookup_connection_value (connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);
            if (encoding != NULL) {
                request->soap_method = (char *)malloc(strlen(ACTION_UPLOAD_PHOTO) + 1);
        	strcpy(request->soap_method, ACTION_UPLOAD_PHOTO);
		request->pp = MHD_create_post_processor(connection, 1024, &post_iterator, request);
                
                if (request->pp == NULL) {
                    printf("Error creating processor\n");
                    return MHD_NO;
                }
            } else {
                request->data_length = 0;
                request->data = (char *)malloc(request->content_length);
            }
        }
        
        return MHD_YES;
    }
    
    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        if (request->pp != NULL) {
            MHD_post_process(request->pp, upload_data, *upload_data_size);
            
            if (*upload_data_size != 0) {
                *upload_data_size = 0;
                return MHD_YES;
            }
            
            MHD_destroy_post_processor(request->pp);
            request->pp = NULL;
        } else {
            char *dest = &request->data[request->data_length];
            memcpy(dest, upload_data, *upload_data_size);
            request->data_length += *upload_data_size;
            
            if (*upload_data_size != 0) {
                *upload_data_size = 0;
                return MHD_YES;
            }
        }
        
        printf("soap action %s\n", request->soap_method);
        if (DUMP_SOAP) {
            printf("request data\n %s\n", request->data);
        }
        struct Response *response_data = NULL;
        
        if (strcmp(request->soap_method, ACTION_START_SESSION) == 0) {
            response_data = process_start_session(request);
        }
        
        if (strcmp(request->soap_method, ACTION_GET_PHOTO_STATUS) == 0) {
            response_data = process_get_photo_status(request);
        }
        
        if (strcmp(request->soap_method, ACTION_UPLOAD_PHOTO) == 0) {
            response_data = process_upload_photo(request);
        }
        
        if (strcmp(request->soap_method, ACTION_MARK_LAST_PHOTO_IN_ROLL) == 0) {
            response_data = process_mark_last_photo_in_rool(request);
        }
        
        if (response_data == NULL) {
            return MHD_NO;
        }
        
        if (DUMP_SOAP) {
            printf("Response data\n %s\n", response_data->data);
        }
        
        response = MHD_create_response_from_buffer(response_data->data_length,
                                                   (void *)response_data->data,
                                                   MHD_RESPMEM_MUST_COPY);
        
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        free(response_data->data);
        free(response_data);
        
        return ret;
    }

    
    if (0 == strcmp(method, MHD_HTTP_METHOD_GET)) {
        *ptr = NULL;
	const char *response_value = PAGE;
        response = MHD_create_response_from_buffer(strlen(response_value), (void *)response_value, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    return MHD_NO;
}

int main (int argc, char *const *argv) {
    struct MHD_Daemon *http_server;
    int port = 59278;
    
    printf("Starting Eye-Fi server on port %d\n", port);
    http_server = MHD_start_daemon(// MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_POLL,
                          MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
                          // MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG | MHD_USE_POLL,
                          // MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                          port,
                          NULL, NULL, &process_request, NULL,
                          MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
                          MHD_OPTION_END);
    if (http_server == NULL) {
        return 1;
    }
    
    printf("Eye-Fi server running\n");
    while (getchar() != 'Q') {}
    printf("Eye-Fi server stopping\n");
    
    MHD_stop_daemon (http_server);
    return 0;
}
