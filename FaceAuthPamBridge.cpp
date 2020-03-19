//
// Created by hjd on 2019/12/07.
// Modify by hjd on 3/19/20.
//

// code definitions
//   -> 0 means succeed
//   -> 100 means user's 128d config file not found or broken ...
//   -> 101 means machine learning model file not found or broken ...

//   -> 110 camera hardware not found / hardware can not use ...

//   -> 120 means face auth continuous fail count > 3 (continuous succeed 3 times can login)
//   -> 121 means timeout (5 seconds no face detected)

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <sys/wait.h>

void pam_display(pam_handle_t *pamh, int style, char const *message) {

    /* variables for pam_conv->conv (security/pam_appl.h) */
    struct pam_conv *pam_convp;
    struct pam_message *pam_msgp = NULL;
    struct pam_response *pam_resp = NULL;

    /* Fetch conversation pointer */
    if (pam_get_item(pamh, PAM_CONV, (const void **) &pam_convp) != PAM_SUCCESS) {
        syslog(LOG_ERR, "get conversation callback failed");
        return;
    }
    if ((pam_convp == NULL) || (pam_convp->conv == NULL)) {
        syslog(LOG_ERR, "conversation callback is null");
        return;
    }

    /* Prepare pam_message */
    pam_msgp = new pam_message;
    if (pam_msgp == NULL) {
        syslog(LOG_ERR, "pam_message creation memory error");
        return;
    }

    pam_msgp->msg_style = style;
    pam_msgp->msg = message;

    /* Call conversation function to deliver message */
    (pam_convp->conv)(1, (const struct pam_message **) &pam_msgp, &pam_resp, pam_convp->appdata_ptr);

    delete pam_msgp;
    delete pam_resp;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,
                     int flags,
                     int argc,
                     const char **argv) {
    printf("#### #### pam_sm_chauthtok executed ...\n");
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("#### #### pam_sm_setcred executed ...\n");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("#### #### pam_sm_acct_mgmt executed ...\n");
    return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("#### #### pam_sm_authenticate executed ...\n");

    pam_message msg;

    msg.msg_style = PAM_PROMPT_ECHO_OFF;      //	1
    msg.msg_style = PAM_PROMPT_ECHO_ON;       //	2
    msg.msg_style = PAM_ERROR_MSG;            //	3
    msg.msg_style = PAM_TEXT_INFO;            //	4

    msg.msg = "Succeed";

    int retval;

    const char *pUsername;
    retval = pam_get_user(pamh, &pUsername, "Username: ");

    printf("#### authenticate for user : [%s]\n", pUsername);

    if (retval != PAM_SUCCESS) {
        return retval;
    }

    char *executeprocess[4] = {"/home/hjd/CLionProjects/FaceAuth/cmake-build-debug/FaceAuth",
                               "auth",
                               const_cast<char *>(pUsername), NULL};

    pid_t c_pid, pid;
    int status;
    bool isChildProcessNormal = true;

    c_pid = fork();

    if (c_pid == 0) {
        /* CHILD */

        printf("#### start child process\n");

        //execute
        execvp(executeprocess[0], executeprocess);

        //only get here if exec failed
        perror("#### start child process failed");

        isChildProcessNormal = false;

        pam_display(pamh, PAM_ERROR_MSG, "Open Realsense Camera Failed");

        return PAM_AUTH_ERR;
    } else if (c_pid > 0) {
        /* PARENT */

        if ((pid = wait(&status)) < 0) {
            perror("#### wait error");
            pam_display(pamh, PAM_ERROR_MSG, "Close Realsense Camera Failed");
            return PAM_AUTH_ERR;
        }

        if (isChildProcessNormal == false) {
            perror("#### Child process creation error");
            pam_display(pamh, PAM_ERROR_MSG, "Child process creation error");
            return PAM_AUTH_ERR;
        }

        printf("#### Child Process return code is [%d]\n", WEXITSTATUS(status));

        switch (WEXITSTATUS(status)) {
            case 0:
                return PAM_SUCCESS;
            case 1:
                pam_display(pamh, PAM_TEXT_INFO, "User face information not found");
                break;
            case 2:
                pam_display(pamh, PAM_ERROR_MSG, "Wrong face try too much time");
                break;
            case 10:
                pam_display(pamh, PAM_ERROR_MSG, "Model file lost");
                break;
            case 11:
                pam_display(pamh, PAM_ERROR_MSG, "Camera not found or broken");
                break;
            case 20:
                pam_display(pamh, PAM_ERROR_MSG, "Timeout");
                break;
            default:
                pam_display(pamh, PAM_ERROR_MSG, "Unknown Error");
                break;
        }
    } else {
        perror("#### fork failed");
        //_exit(1);
        pam_display(pamh, PAM_ERROR_MSG, "System Error");
        return PAM_AUTH_ERR;
    }

    return PAM_AUTH_ERR;
}