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
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define PASSWORD_SIZE (32)
#define HASH_SIZE (13)
#define NOUSER (-1)
#define MAX_FAILED_LOGINS (5)
#define MUST_RESET_PASSWORD (10)
#define LOCKED_ACCOUNT (-1)
#define TERM "/usr/bin/xterm"

static volatile int was_interrupted = 0;

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
  while ((c = getchar())!= '\n' && c != EOF && i < PASSWORD_SIZE && !was_interrupted){
    if (was_interrupted) return;
    password[i++] = c;
  }
  password[i] = '\0';

  // Set STDIN settings to the previously stored ones
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
}

void reset_password(struct pwdb_passwd *p){
  // Unnecessary? Not sure about lab instructions.
  char password[PASSWORD_SIZE];
  char confirm[PASSWORD_SIZE];
  while (1){
    read_password(password);
    read_password(confirm);
    if (strcmp(password, confirm) == 0) break;
  }
  char *crypted = crypt(password, p->pw_passwd);
  p->pw_passwd=crypted;
  pwdb_update_user(p);
}

void login_success(struct pwdb_passwd *p){
  p->pw_failed = 0;
  p->pw_age++;
  if (p->pw_age >= MUST_RESET_PASSWORD) reset_password(p);
  else pwdb_update_user(p);
}

int is_locked_out(struct pwdb_passwd *p){
  if (p->pw_failed == LOCKED_ACCOUNT) return 1;
  else return 0;
}

void login_failed(struct pwdb_passwd *p){
  p->pw_failed++;
  if (p->pw_failed >= MAX_FAILED_LOGINS) p->pw_failed = -1;
  pwdb_update_user(p);
}

int login(struct pwdb_passwd *info){
  char username[USERNAME_SIZE];
  char password[PASSWORD_SIZE];
  /*
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */

  read_username(username);
  if (was_interrupted) {
    return 1;
  }

  info = pwdb_getpwnam(username);

  if (info == NULL){
    // printf(pwdb_err2str(NOUSER));
    return 1;
  }

  if (is_locked_out(info)) {
    printf("Locked out!\n");
    return 1;
  }

  read_password(password);
  if (was_interrupted) return 1;
  char *crypted = crypt(password, info->pw_passwd);

  if (strncmp(info->pw_passwd, crypted, HASH_SIZE) == 0){
    login_success(info);
    printf("Logged in!\n");
    return 0;
  }
  else {
    login_failed(info);
    printf("No!\n");
    return 1;
  }
}

void interrupt_handler(int arg){
  was_interrupted = 1;
  signal(SIGINT, interrupt_handler);
}


int main(int argc, char **argv)
{
  signal(SIGINT, interrupt_handler);
  while (1){
    was_interrupted = 0;
    struct pwdb_passwd p;
    int failed = login(&p);
    if (!failed) {
      int pid = fork();
      int status = 0;
      if (pid==0) {
        /* This is the child process. Run an xterm window */
        setuid(p.pw_uid);
        execl(TERM,TERM,"-e",&p.pw_shell,"-l",NULL);
        _exit(-1);
      } else if (pid < 0) { /* Fork failed */
        printf("Fork faild\n");
        status = -1;
      } else {
        /* This is parent process. Wait for child to complete */
        if (waitpid(pid, &status, 0) != pid) {
          status = -1;
        }
      }
    }
  }
}
