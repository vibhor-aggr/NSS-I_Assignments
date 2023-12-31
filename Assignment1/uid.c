#include <stdio.h>
#include <pwd.h>

#if 0
int main() {
    // Replace 1000 with the UID you want to map to a username
    uid_t uid = 1000;
    
    const char* uname = getUsrName(uid);
    printf("Username for UID %d: %s\n", uid, uname);
    return 0;
}
#endif

const char* getUsrName(uid_t uid)
{    
    struct passwd *pw_entry;
    
    pw_entry = getpwuid(uid);
    
    if (pw_entry == NULL) {
        perror("getpwuid");
        return NULL;
    }
    
    return pw_entry->pw_name;
}

