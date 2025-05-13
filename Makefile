CFLAGS	= -lsodium
CC		= gcc

NAME	= ransonware

SRC		= ransonware.c
OBJ		= ${SRC:.c=.o}

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

all: ${NAME}

${NAME}: ${OBJ}
	${CC} ${CFLAGS} -o ${NAME} ${OBJ} 

clean:
	rm -rf ${OBJ}

fclean: clean
	rm -rf ${NAME}

re:  fclean all

.PHONY : clean all fclean re
