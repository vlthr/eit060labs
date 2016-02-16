/*
 * Shows user info from local pwfile.
 *
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define PASSWORD_SIZE (32)
#define HASH_SIZE (13)
#define NOUSER (-1)

int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
	return 0;
  } else {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

void do_login(){

}

void read_password(char password[])
{
  static struct termios oldt, newt;
  int i = 0;
  int c;

  // Get current STDIN attributes and put them in oldt
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;

  // Set the ECHO bit to prevent echoing output to the terminal
  newt.c_lflag &= ~(ECHO);

  // Setting STDIN attributes to the new settings
  tcsetattr( STDIN_FILENO, TCSANOW, &newt);

  // Read password
  while ((c = getchar())!= '\n' && c != EOF && i < PASSWORD_SIZE){
    password[i++] = c;
  }
  password[i] = '\0';

  // Set STDIN settings to the previously stored ones
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

}

int login(){
  char username[USERNAME_SIZE];
  char password[PASSWORD_SIZE];
  /*
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */

  read_username(username);
  read_password(password);

  struct pwdb_passwd *info = pwdb_getpwnam(username);

  char *crypted = crypt(password, info->pw_passwd);

  if (info == NULL){
    printf(pwdb_err2str(NOUSER));
    return 1;
  }

  if (strncmp(info->pw_passwd, crypted, HASH_SIZE) == 0){
    // Equal
    printf("Logged in!\n");
  }
  else {
    printf("No!\n");
  }

  return 0;
}

int main(int argc, char **argv)
{
  while (!login());
}
