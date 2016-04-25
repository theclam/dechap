#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/md5.h>

#include "dechap.h"

#define SWVERSION "v0.5 alpha"
#define SWRELEASEDATE "October 2016"

// "dechap" attempts to recover credentials from packet captures of PPPoE, RADIUS and L2TP CHAP authentications.
// It can also now work with OSPFv2 and BGP packets :)
// Written by Foeh Mannay
// Please refer to http://networkbodges.blogspot.com for more information about this tool.
// This software is released under the Modified BSD license.

params_t *parseParams(int argc, char *argv[]){
    // Returns a struct with various parameters or NULL if invalid
    unsigned int i = 1;
    params_t *parameters = (params_t*)malloc(sizeof(params_t));
    if(parameters == NULL) return(NULL);

    // There must be 4 parameters
    if(argc != 5) return(NULL);

    // Set some defaults
    parameters->capfile = NULL;
    parameters->wordfile = NULL;

    // Look for the various flags, then store the corresponding value
    while(i < argc){
        if(strcmp(argv[i],"-c") == 0){
            parameters->capfile = argv[++i];
            i++;
            continue;
        }
        if(strcmp(argv[i],"-w") == 0){
            parameters->wordfile = argv[++i];
            i++;
            continue;
        }
        // If we get any unrecognised parameters just fail
        return(NULL);
    }

    // If the input files still aren't set, bomb
    if(parameters->capfile == NULL || parameters->wordfile == NULL) return(NULL);

    return(parameters);
}

auth_instance_t *decap(char *data, unsigned int length, char type, auth_instance_t *ai){
// The decap() function takes in a  pointer to a (partial) frame, the size of the 
// data, a hint indicating the encap type and a pointer to an authentication instance
// template which is populated as the various layers of encap are stripped away.
    int chaplen = 0;
    int vlen = 0;
    int pos = 0;

    // Some sanity checks
    if(data == NULL) return(NULL);
    if(ai == NULL) return(NULL);

    // Based on current encap type, try to determine what the next encap type will be
    switch(type){
        case ETHERNET:
            if(length < 14) return(NULL);
            
            // Populate the source and destination MACs then check the EtherType
            memcpy(ai->dmac, data, 6);
            memcpy(ai->smac, data + 6, 6);
            
            // VLAN tag next?
            if(memcmp(data+12, "\x81\x00", 2) == 0 || memcmp(data+12, "\x91\x00", 2) == 0){
                return(decap(data + 14, length - 14, VLAN, ai));
            }
            // MPLS tag next?
            if(memcmp(data+12, "\x88\x47", 2) == 0){
                return(decap(data + 14, length - 14, MPLS, ai));
            }
            // PPPoE session data next?
            if(memcmp(data+12, "\x88\x64", 2) == 0){
                return(decap(data + 14, length - 14, PPPoE, ai));
            }
            // IP next?
            if(memcmp(data+12, "\x08\x00",2) == 0){
                return(decap(data + 14, length - 14, IPv4, ai));
            }
            return(NULL);
        break;
        case VLAN:
            if(length < 4) return(NULL);
            // Populate the VLAN ID(s):
            // If there is already an inner VLAN, move it to an outer
            if(ai->cvlan != 0) ai->svlan = ai->cvlan;
            // Store this VLAN as the inner
            ai->cvlan = (256*data[0] & 15) + data[1];
            
            // Now  determine the next encap type from the EtherType
            // VLAN tag next?
            if(memcmp(data+2, "\x81\x00", 2) == 0 || memcmp(data+2, "\x91\x00",2) == 0){
                return(decap(data + 4, length - 4, VLAN, ai));
            }
            // MPLS tag next?
            if(memcmp(data+2, "\x88\x47", 2) == 0){
                return(decap(data + 4, length - 4, MPLS, ai));
            }
            // PPPoE session data next?
            if(memcmp(data+2, "\x88\x64", 2) == 0){
                return(decap(data + 4, length - 4, PPPoE, ai));
            }
                        // IP next?
                        if(memcmp(data+2, "\x08\x00", 2) == 0){
                                return(decap(data + 4, length - 4, IPv4, ai));
                        }
            return(NULL);

        break;
        case MPLS:
            if(length < 4) return(NULL);
            // Check bottom of stack bit to decide whether to keep stripping MPLS or try for Ethernet
            if((data[2] & '\x01') == 0){
                return(decap(data + 4, length - 4, MPLS, ai));        // Not BOS, more MPLS
            }
            if(length > 4 && (data[4] & '\xf0') == '\x40'){
                return(decap(data + 4, length - 4, IPv4, ai));        // BOS, presume IPv4
            } else { 
                return(decap(data + 4, length - 4, ETHERNET, ai));    // BOS - try for Ethernet
            }
        break;
        case PPPoE:
            // Only a PPP header can follow a PPPoE session header
            if(length < 6) return(NULL);
            // Populate the PPPoE SID
            ai->pppoesid = (data[2] * 256) + data[3];
            return(decap(data + 6, length - 6, PPP, ai));
        break;
        case PPP:
            // If the protocol is CHAP, decode it. If not, bail out.
            if(length < 2) return(NULL);
            if(memcmp(data, "\xc2\x23", 2) == 0){
                return(decap(data + 2, length - 2, CHAP, ai));
            }
            else return(NULL);
        break;
        case CHAP:
            if(length < 4) return(NULL);
            // We only care about challenges and responses, so success and failure messages are ignored.
            switch(data[0]){
                case CHAP_CHALLENGE:    // If it's a challenge:
                    // Populate the auth ID, challenge data and challenge length.
                    ai->authid = data[1];
                    ai->cr = CHAP_CHALLENGE;
                    ai->length = data[4];
                    ai->challenge_data = (char*)malloc(ai->length);
                    if(ai->challenge_data == NULL){
                        printf("Could not malloc %u bytes for CHAP challenge data!\n",ai->length);
                        return(NULL);
                    }
                    memcpy(ai->challenge_data, data + 5, ai->length);
                    return(ai);
                break;
                case CHAP_RESPONSE:        // If it's a response:
                    // Populate the auth ID, response data and username.
                    ai->authid = data[1];
                    ai->cr = CHAP_RESPONSE;
                    ai->length = data[4];    // Should always be 16 but why take chances?
                    ai->response_data = (char*)malloc(ai->length);
                    if(ai->response_data == NULL){
                        printf("Could not malloc %u bytes for CHAP response data!\n",ai->length);
                        return(NULL);
                    }
                    memcpy(ai->response_data, data + 5, ai->length);
                    chaplen = (256 * data[2]) + data[3];
                    ai->username = (char*)malloc(chaplen - (ai->length + 4));
                    if(ai->username == NULL){
                        printf("Could not malloc %u bytes for CHAP username!\n",chaplen - (ai->length + 4));
                        return(NULL);
                    }
                    memcpy(ai->username, data + 5 + ai->length, chaplen - (ai->length + 5));
                    ai->username[chaplen - (ai->length + 5)] = '\x00';    // Null-terminate the username for later use.
                    return(ai);
                break;
                default:            // We have no interest in success or failure messages as there is nothing to attack.
                    return(NULL);
            }
        break;
        case IPv4:
            // If the protocol is IPv4 we may find some UDP RADIUS / L2TP messages
            if(length < 20) return(NULL);
            if(length < 4 * (data[0] & 15)) return(NULL);
            ai->ip_ptr = data;
            
            if(data[9] == '\x11'){    // UDP
                return(decap(data + (4 * (data[0] & 15)), length - (4 * (unsigned char)(data[0] & 15)), UDP, ai));
            } 

            if(data[9] == '\x59'){    //OSPFv2
                return(decap(data + (4 * (data[0] & 15)), length - (4 * (unsigned char)(data[0] & 15)), OSPFv2, ai));
                        }

            if(data[9] == '\x06'){  //TCP
                    return(decap(data + (4 * (data[0] & 15)), length - (4 * (unsigned char)(data[0] & 15)), TCP, ai));
            } 
            return(NULL);

        break;
        case OSPFv2:
            // If the protocol is OSPF IGP, check for version 2 packets with MD5 auth.
            if(length < 24) return(NULL);        // Must have full header
            if(data[0] != '\x02') return(NULL);     // OSPF version check
            if(memcmp(data + 12, "\x00\x00\x00\x02",4) != 0) return(NULL); // Not MD5 auth
            vlen = (((unsigned char)data[2]) * 256 + (unsigned char)data[3]);
            if(length < (vlen + (unsigned char)data[19])) return(NULL);    // Header lies!
            
            // Assuming the OSPF is sane, grab a copy of the packet contents
            ai->cr = OSPF_MD5;
            ai->challenge_data = (char*)malloc(vlen);
            if(ai->challenge_data == NULL){
                printf("Error! Could not allocate memory for OSPF packet data!\n");
                return(NULL);
            }
            memcpy(ai->challenge_data, data, vlen);
            ai->length = vlen;
            // Now save a copy of the resulting hash
            ai->response_data = (char*)malloc((unsigned char)data[19]);
            if(ai->response_data == NULL){
                printf("Error! Could not allocate memory for OSPF packet data!\n");
                return(NULL);
            }
            memcpy(ai->response_data, data + vlen, (unsigned char)data[19]);
            ai->username = (char*)malloc(40);
            if(ai->username == NULL){
                printf("Error! Could not allocate memory for hostname!\n");
                return(NULL);
            }
            // Set the username to indicate the IP of the sending router and the key ID
            snprintf(ai->username, 39, "OSPF host %u.%u.%u.%u key %u", 
                (unsigned char)ai->ip_ptr[12],
                (unsigned char)ai->ip_ptr[13],
                (unsigned char)ai->ip_ptr[14],
                (unsigned char)ai->ip_ptr[15],
                (unsigned char)data[18]);
            return(ai);

                case TCP:
                        // If the protocol is TCP, check for MD5 signature (a la RFC 2385 for BGP)
                        if(length < 40) return(NULL);                    // Not enough frame left for a signature

                        if((unsigned char)(data[12] & '\xf0') < '\xa0' ) return(NULL);  // Header too short for MD5 signature

                        for(pos=20; data[pos] != 0; pos = pos + data[pos+1]){        // Cycle through the options, looking for
                                if(data[pos] == 19){                    // Option kind 19 for TCP MD5 signature

                                        vlen = length - ((unsigned char)(data[12] & '\xf0') / 4);        // data length
                                        
                    // Save a copy of the pseudoheader
                    ai->length = 12 + 20 + vlen;
                    ai->challenge_data = (char*)malloc(ai->length);
                    if(ai->challenge_data == NULL){
                        printf("Error! Could not allocate memory for hash input!\n");
                        return(NULL);
                    }
                                                // As per RFC2385, the pseudoheader consists of:
                    memcpy(ai->challenge_data, ai->ip_ptr + 12, 8);        // Source and destination IP,
                    ai->challenge_data[8] = 0;                // zero padded...
                                        ai->challenge_data[9] = ai->ip_ptr[9];            // ... protocol number
                                        ai->challenge_data[10] = (unsigned char)(length / 256);    // and segment length.
                                        ai->challenge_data[11] = (unsigned char)(length % 256);
                                        memcpy(ai->challenge_data+12, data, 16);        // We also add the TCP header...
                                        memcpy(ai->challenge_data+28, "\x00\x00\x00\x00", 4);    // ... with a checksum of zero assumed
                                        memcpy(ai->challenge_data+32, data + ((unsigned char)(data[12] & '\xf0') / 4), vlen);    // and the segment data

                            // Save a copy of the provided signature hash
                                   ai->response_data = (char*)malloc(16);
                                if(ai->response_data == NULL){
                                        printf("Error! Could not allocate memory for hash!\n");
                                        return(NULL);
                                }
                    // Build a descriptive username
                    memcpy(ai->response_data, data + pos + 2, 16);
                    ai->username = (char*)malloc(45);
                    if(ai->username == NULL){
                                        printf("Error! Could not allocate memory for hostname!\n");
                                        return(NULL);
                                }
                                // Set the username to the source and destination IPs
                                snprintf(ai->username, 39, "TCP from %u.%u.%u.%u to %u.%u.%u.%u",
                                        (unsigned char)ai->ip_ptr[12],
                                        (unsigned char)ai->ip_ptr[13],
                                        (unsigned char)ai->ip_ptr[14],
                                        (unsigned char)ai->ip_ptr[15],
                                                (unsigned char)ai->ip_ptr[16],
                                                (unsigned char)ai->ip_ptr[17],
                                                (unsigned char)ai->ip_ptr[18],
                                                (unsigned char)ai->ip_ptr[19]);

                                        // Set the type to attack
                                        ai->cr = IP_MD5;

                                return(ai);
                }
                        }

                        return(NULL);

                break;

        case UDP:
            // If the protocol is UDP, check for RADIUS / L2TP port numbers
            if(length < 8) return(NULL);
            
            if(memcmp(data + 2, "\x07\x14",2) == 0){    // RADIUS port 1812
                return(decap(data + 8, length - 8, RADIUS, ai));
            } else if(memcmp(data + 2, "\x06\xa5",2) == 0){
                return(decap(data + 8, length - 8, L2TP, ai));
            } else return(NULL);
        break;
        case RADIUS:
            // If a RADIUS access request packet is found, we can try for a challenge / reponse pair.
            if(length < 20) return(NULL);                        // Must be large enough for a full RADIUS header
            if(data[0] != '\x01') return(NULL);                    // Only interested in Access-Requests
            vlen = (256*(unsigned char)data[2])+(unsigned char)data[3];
            if(vlen > length) return(NULL);    // If the header says length > remaining data, bail out
            
            return(decap(data + 20, vlen - 20, RADAVP, ai));
        break;
        case RADAVP:
            // Work through the RADIUS AVPs to try and gather auths.
            if(length < 2 || (char)data[1] > length){
                // If we are at the end but we have an authentication, return it.
                if(ai->challenge_data != NULL && ai->response_data != NULL){
                    ai->cr = CHAP_BOTH;
                    return(ai);
                } else return(NULL);
            }
            vlen = (unsigned char)data[1] - 2;
            switch(data[0]){
                case '\x03':        // CHAP response data
                    ai->authid = data[2];
                    ai->response_data = (char*)malloc(vlen);
                    if(ai->response_data == NULL){
                        printf("Error! Could not allocate memory for CHAP response data!\n");
                        return(NULL);
                    }
                    memcpy(ai->response_data, data + 3, vlen - 1);
                break;
                case '\x01':        // Username
                    ai->username = (char*)malloc(vlen + 1);
                    if(ai->username == NULL){
                        printf("Error! Could not allocate memory for username!\n");
                        return(NULL);
                    }
                    memcpy(ai->username, data + 2, vlen);
                    ai->username[vlen]='\x00';    // Don't forget to null terminate it.
                break;
                case '\x3c':        // CHAP challenge data
                    ai->challenge_data = (char*)malloc(vlen);
                    if(ai->challenge_data == NULL){
                        printf("Error! Could not allocate memory for CHAP challenge data!\n");
                        return(NULL);
                    }
                    memcpy(ai->challenge_data, data + 2, vlen);
                    ai->length = vlen;
                break;
            }
            return(decap(data + vlen + 2, length - (vlen + 2), RADAVP, ai));
        break;
        case L2TP:
            // If we get an L2TP ICCN packet, it may contain a CHAP authentication.
            if(length < 12) return(NULL);
            if((data[1] & '\x0f') != '\x02' || data[0] & '\xcb' != '\xc8') return(NULL);
            vlen = (256*(unsigned char)data[2])+(unsigned char)data[3];
            if(vlen > length) return(NULL);    // If the header says length > remaining data, bail out
            
            return(decap(data + 12, vlen - 12, L2AVP, ai));
        break;
        case L2AVP:
            // Work through the L2TP AVPs to try and gather auths.
            if(length < 6){
                // If we are at the end but we have an authentication, return it.
                if(ai->challenge_data != NULL && ai->response_data != NULL){
                    ai->cr = CHAP_BOTH;
                    return(ai);
                } else return(NULL);
            }
            vlen = (256 * ((unsigned char)data[0] & 3)) + (unsigned char)data[1];
            if(vlen > length) return(NULL);
            
            // If this isn't a reserved AVP, we're not interested.
            if(memcmp(data + 2, "\x00\x00\x00", 3) != 0) return(decap(data + vlen, length - vlen, L2AVP, ai));
            
            switch(data[5]){
                case '\x00':        // Control message type
                    // CHAP should only be in an ICCN message, so abandon anything else
                    if(memcmp(data + 6, "\x00\x0c", 2) != 0){
                        return(NULL);
                    }
                break;
                case '\x1e':        // Username
                    ai->username = (char*)malloc(vlen - 5);
                    if(ai->username == NULL){
                        printf("Error! Could not allocate memory for username!\n");
                        return(NULL);
                    }
                    memcpy(ai->username, data + 6, vlen - 6);
                    ai->username[vlen-6]='\x00';    // Don't forget to null terminate it.
                break;
                case '\x1f':        // CHAP challenge data
                    ai->challenge_data = (char*)malloc(vlen - 6);
                    if(ai->challenge_data == NULL){
                        printf("Error! Could not allocate memory for CHAP challenge data!\n");
                        return(NULL);
                    }
                    memcpy(ai->challenge_data, data + 6, vlen - 6);
                    ai->length = vlen - 6;
                break;
                case '\x20':        // Authentication ID
                    ai->authid = (unsigned char)data[7];
                break;
                case '\x21':        // CHAP response data
                    ai->response_data = (char*)malloc(vlen - 6);
                    if(ai->response_data == NULL){
                        printf("Error! Could not allocate memory for CHAP response!\n");
                        return(NULL);
                    }
                    memcpy(ai->response_data, data + 6, vlen - 6);
                break;    
            }
            return(decap(data + vlen, length - vlen, L2AVP, ai));
        break;
    }
    return(NULL);
}

void clean(auth_instance_t *ai){
// Populates an authentication instance with default values
    if(ai == NULL) return;
    
    memcpy(ai->dmac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(ai->smac, "\x00\x00\x00\x00\x00\x00", 6);
    ai->svlan = 0;
    ai->cvlan = 0;
    ai->pppoesid = 0;
    ai->authid = 0;
    ai->cr = CHAP_NONE;
    ai->length = 0;
    ai->challenge_data = NULL;
    ai->response_data = NULL;
    ai->username = NULL;
}

auth_list_item_t *graft(auth_list_item_t *root, auth_list_item_t *newitem){
// Adds an authentication list item to an existing list (or NULL), returning
// a pointer to the root.
    auth_list_item_t *current = root;
    if(root == NULL) return(newitem);

    while(current->next != NULL) current = current->next;
    current->next = newitem;
    newitem->prev = current;
    return(root);
}

auth_list_item_t *node(auth_instance_t *item){
// Creates an authentication list item from an authentication instance.
    auth_list_item_t *n = (auth_list_item_t*)malloc(sizeof(auth_list_item_t));
    
    if(n == NULL) return(NULL);
    n->item = item;
    n->next = NULL;
    n->prev = NULL;
    return(n);
}

puzzle_t *addpuzzle(puzzle_t *root, auth_list_item_t *challenge, auth_list_item_t *response, char type){
// Generates a puzzle from a challenge / response pair and appends it to the list of puzzles.
    puzzle_t *current;
    puzzle_t *newnode = (puzzle_t*)malloc(sizeof(puzzle_t));
    
    if(newnode == NULL){
        printf("Error: Could not allocate memory for puzzle!");
        return(root);
    }
    
    newnode->next = NULL;
    newnode->authid = challenge->item->authid;
    newnode->length = challenge->item->length;
    newnode->challenge = challenge->item->challenge_data;
    newnode->response = response->item->response_data;
    newnode->username = response->item->username;
    newnode->password = NULL;
    newnode->type = type;
    
    if(root == NULL) return(newnode);
    for(current = root; current->next != NULL; current = current->next);
    current->next = newnode;
    return(root);
}

puzzle_t *pair_up(auth_list_item_t *chaps){
    puzzle_t            *puzzles = NULL;
    auth_list_item_t     *response = NULL,
                        *challenge = NULL;

    // Now cycle through the responses and find their corresponding challenges
    // This is done by working forward through the list until we find a response,
    // then working backwards from there to find the most recent challenge that 
    // matches that PPP session based on MAC address, S&C VLAN, PPPoE session
    // ID and authentication ID.
    for(response = chaps; response != NULL; response = response->next){
        
        if(response->item->cr == OSPF_MD5){
            challenge = response;
            puzzles = addpuzzle(puzzles, challenge, response, OSPF_MD5);
            continue;
        }
        if(response->item->cr == IP_MD5){
            challenge = response;
            puzzles = addpuzzle(puzzles, challenge, response, IP_MD5);
            continue;
        }
        if(response->item->cr == CHAP_CHALLENGE) continue;
        if(response->item->cr == CHAP_BOTH){
            challenge = response;
            puzzles = addpuzzle(puzzles, challenge, response, CHAP);
            continue;
        }
        for(challenge = response; challenge != NULL; challenge = challenge->prev){
            // Go through previous challenges to find one matching our response
            if(challenge->item->cr == CHAP_CHALLENGE &&
                memcmp(challenge->item->smac, response->item->dmac, 6) == 0 &&
                memcmp(challenge->item->dmac, response->item->smac, 6) == 0 &&
                challenge->item->svlan == response->item->svlan &&
                challenge->item->cvlan == response->item->cvlan &&
                challenge->item->pppoesid == response->item->pppoesid &&
                challenge->item->authid == response->item->authid)
                    break;
        }
        // If we can't find a matching challenge then we can't do anything.
        if(challenge == NULL) continue;
        
        // If we did find a match, create an entry in our list of hashes.
        puzzles = addpuzzle(puzzles, challenge, response, CHAP);
    }
    return(puzzles);
}

puzzle_t *parse_pcap(FILE *capfile){
    char                 *memblock = NULL;
    auth_list_item_t    *chaps = NULL;
    auth_instance_t        *ai = NULL,
                        *decapai = NULL;
    guint32                caplen = 0;
    puzzle_t            *puzzles = NULL,
                        *p = NULL;
    
    // Start parsing the capture file:
    rewind(capfile);
    clearerr(capfile);
    memblock = (char*)malloc(sizeof(pcap_hdr_t));
    if(memblock == NULL){
        printf("Insufficient memory to load capture header.\n");
        return(NULL);
    }
    // Read the pcap header
    if(fread (memblock, 1, sizeof(pcap_hdr_t), capfile) != sizeof(pcap_hdr_t)){
        printf("Truncated capture file header - aborting.\n");
        free(memblock);
        return(NULL);
    }
    // Verify the magic number in the header indicates a pcap file
    if(((pcap_hdr_t*)memblock)->magic_number != 2712847316){
        printf("\nError!\nThis is not a valid pcap file. If it has been saved as pcap-ng\nconsider converting it to original pcap format with tshark or similar.\n");
        free(memblock); 
        return(NULL);
    }
    
    // Generate an authentication instance template ready to use
    ai = (auth_instance_t*)malloc(sizeof(auth_instance_t));
    if(ai == NULL){
        printf("Error: could not allocate memory for authentication instance!\n");
        return(NULL);
    }

        // Read in the packets and search for any CHAP. Store the challenges and responses in a list.
    while(feof(capfile) | ferror(capfile) == 0){
        free(memblock);
        // Get the packet record header and examine it for the packet size
        memblock = malloc(sizeof(pcaprec_hdr_t));
        if(memblock == NULL){
            printf("Error: Could not allocate memory for pcap record header!\n");
            return(NULL);
        }
        if(fread (memblock, 1, sizeof(pcaprec_hdr_t), capfile) != sizeof(pcaprec_hdr_t)){
//            printf("Error: Truncated pcap file reading record header!\n");
            break;
        }
        caplen = ((pcaprec_hdr_t*)memblock)->incl_len;
        free(memblock);
        memblock = malloc(caplen);
        if(memblock == NULL){
            printf("Error: Could not allocate memory for pcap record header!\n");
            return(NULL);
        }
        // Get the actual packet data and attempt to parse it
        if(fread (memblock, 1, caplen, capfile) != caplen){
            printf("Error: Truncated pcap file reading capture!\n");
            break;
        }
        
        // Start with a fresh authentication instance template.
        clean(ai);
        decapai = decap(memblock, caplen, ETHERNET, ai);
        if(decapai != NULL){
        // We found some CHAP, so store it
            // Generate a fresh authentication instance template for use in the next round
            ai = (auth_instance_t*)malloc(sizeof(auth_instance_t));
            if(ai == NULL){
                printf("Error: could not allocate memory for authentication instance!\n");
                return(NULL);
            }
            // Then store the current authentication instance in a list
            chaps = graft(chaps, node(decapai));
        }
    }
    free(memblock);

    return(pair_up(chaps));
}

void crack(puzzle_t *puzzles, FILE *wordfile){
// Attempts to solve challenge / response "puzzles" using candidate passwords
// from a word list.
 
    puzzle_t            *currentpuzzle = NULL;
    char                *password = (char*)malloc(256),
                        *base,
                        hash[16];
    int                    pwlen = 0;

    for(currentpuzzle = puzzles; currentpuzzle != NULL; currentpuzzle = currentpuzzle->next){
        base = (char*)malloc(currentpuzzle->length + 257);
        rewind(wordfile);
        while(feof(wordfile) == 0){
            if(fgets(password, 255, wordfile) == NULL) break;
            pwlen = strlen(password);
            if(pwlen > 0 && password[pwlen-1] == '\n') password[pwlen-1] = '\x00';
            if(currentpuzzle->type == CHAP){
                // Next job is to concatenate the auth ID with the plaintext password and the challenge data:
                base[0] = (char)currentpuzzle->authid;
                strcpy(base+1, password);
                memcpy(base+pwlen, currentpuzzle->challenge, currentpuzzle->length);
                // Obtain the MD5 hash of this and compare it to the one in the CHAP response:
                MD5(base, pwlen + currentpuzzle->length , hash);
                if(memcmp(hash, currentpuzzle->response, 16) == 0){
                    printf("Found password \"%s\" for user %s.\n", password, currentpuzzle->username);
                    currentpuzzle->password = strdup(password);
                    break;
                }
            } else if(currentpuzzle->type == OSPF_MD5){
                // Hash is run against the packet contents, plus a zero padded password field of exactly 16 bytes length
                memcpy(base, currentpuzzle->challenge, currentpuzzle->length);
                memcpy(base+currentpuzzle->length, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
                strcpy(base+currentpuzzle->length, password);
                MD5(base, 16 + currentpuzzle->length, hash);
                if(memcmp(hash, currentpuzzle->response, 16) == 0){
                    printf("Found password \"%s\" for %s.\n", password, currentpuzzle->username);
                    currentpuzzle->password = strdup(password);
                    break;
                }
            } else if(currentpuzzle->type == IP_MD5){
                // Hash is run against the pseudoheader and segment contents, plus a variable length password field
                memcpy(base, currentpuzzle->challenge, currentpuzzle->length);
                strcpy(base+currentpuzzle->length, password);
                MD5(base, currentpuzzle->length + pwlen -1, hash);
                if(memcmp(hash, currentpuzzle->response, 16) == 0){
                    printf("Found password \"%s\" for %s.\n", password, currentpuzzle->username);
                    currentpuzzle->password = strdup(password);
                    break;
                }
            }
        }
        if(currentpuzzle->password == NULL) printf("Unable to find a password for %s.\n", currentpuzzle->username);
        free(base);
    }
}

/*
 * The main function basically just calls other functions to do the work.
**/

int main(int argc, char **argv)
{
    params_t            *parameters = NULL;
    FILE                *capfile = NULL,
                        *wordfile = NULL;
    auth_list_item_t     *chaps = NULL;
    puzzle_t            *puzzles = NULL;
    
    /**
     * Parse our command line parameters and verify they are usable. If not, show help.
    **/
    parameters = parseParams(argc, argv);
    if(parameters == NULL){
        printf("\nBruteforce attack for captured PPPoE, RADIUS, L2TP, OSPF and BGP traffic.\n");
        printf("Version %s, %s\n\n", SWVERSION, SWRELEASEDATE);
        printf("Usage: %s -c capfile.pcap -w wordlist.txt\n\n", argv[0]);
        printf("Where capfile is a tcpdump-style .cap file containing PPPoE, RADIUS\n");
        printf("or L2TP CHAP authentications or MD5 authenticated OSPF / BGP packets and\n");
        printf("wordfile is a plain text file containing password guesses. VLAN tags\n");
        printf("and MPLS labels are automatically stripped.\n\n");
        return(1);
    }
    
    // Attempt to open the capture file and word list:
    capfile = fopen(parameters->capfile,"rb");
    if (capfile == NULL) {
        printf("\nError!\nUnable to open capture file!\n");
        return(1);
    }
    wordfile = fopen(parameters->wordfile, "r");
    if(wordfile == NULL){
        printf("Error - could not open wordfile!\n");
        return(1);
    }
    
    // Parse the pcap file and store any authentications found in the list:
    puzzles = parse_pcap(capfile);
    fclose(capfile);
    
    // Now we have our puzzles, let's crack some passwords.
    if(puzzles == NULL){
        printf("No attackable authentications found.\n");
        return(1);
    }
    crack(puzzles, wordfile);
    fclose(wordfile);
    
    return(0);
}

