/* channel-func.c -- SSH channel manipulation functions.
 *
 * Copyright (C) 2013, 2014, 2015 Artyom V. Poptsov <poptsov.artyom@gmail.com>
 *
 * This file is part of Guile-SSH.
 *
 * Guile-SSH is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Guile-SSH is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Guile-SSH.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <libguile.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include "common.h"
#include "error.h"
#include "channel-type.h"
#include "session-type.h"

#ifdef HAVE_LIBSSH_0_7_3
#define ssh_forward_listen ssh_channel_listen_forward
#define ssh_forward_cancel ssh_channel_cancel_forward
#endif


/* Procedures */

SCM_DEFINE (guile_ssh_channel_open_session, "channel-open-session", 1, 0, 0,
            (SCM channel),
            "\
Open a new session and mark the channel CHANNEL as opened port.\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_open_session
{
  struct channel_data *data = _scm_to_channel_data (channel);
  int res;
  GSSH_VALIDATE_CHANNEL_DATA (data, channel, FUNC_NAME);
  res = ssh_channel_open_session (data->ssh_channel);
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (data->ssh_channel);
      guile_ssh_session_error1 (FUNC_NAME, session, channel);
    }

  SCM_SET_CELL_TYPE (channel, SCM_CELL_TYPE (channel) | SCM_OPN);

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

/* Run a shell command CMD without an interactive shell. */
SCM_DEFINE (guile_ssh_channel_request_exec, "channel-request-exec", 2, 0, 0,
            (SCM channel, SCM cmd),
            "\
Run a shell command CMD without an interactive shell.\
")
#define FUNC_NAME s_guile_ssh_channel_request_exec
{
  struct channel_data *data = _scm_to_channel_data (channel);
  int res;
  char *c_cmd;                  /* Command to execute. */

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT (scm_is_string (cmd), cmd, SCM_ARG2, FUNC_NAME);

  c_cmd = scm_to_locale_string (cmd);
  res = ssh_channel_request_exec (data->ssh_channel, c_cmd);
  free (c_cmd);
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (data->ssh_channel);
      guile_ssh_session_error1 (FUNC_NAME, session, scm_list_2 (channel, cmd));
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_get_exit_status,
            "channel-get-exit-status", 1, 0, 0,
            (SCM channel),
            "\
Get the exit status of the channel (error code from the executed \
instruction).  Return the exist status, or #f if no exit status has been \
returned (yet). \
")
#define FUNC_NAME s_guile_ssh_channel_get_exit_status
{
  struct channel_data *cd = _scm_to_channel_data (channel);
  int res;

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);

  res = ssh_channel_get_exit_status (cd->ssh_channel);
  return (res == SSH_ERROR) ? SCM_BOOL_F : scm_from_int (res);
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_request_send_exit_status,
            "channel-request-send-exit-status", 2, 0, 0,
            (SCM channel, SCM exit_status),
            "\
Send the exit status to the remote process (as described in RFC 4254, section\n\
6.10).\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_request_send_exit_status
{
  struct channel_data *cd = _scm_to_channel_data (channel);
  int res;

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT (scm_is_unsigned_integer (exit_status, 0, UINT32_MAX), exit_status,
              SCM_ARG2, FUNC_NAME);

  res = ssh_channel_request_send_exit_status (cd->ssh_channel,
                                              scm_to_uint32 (exit_status));
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (cd->ssh_channel);
      guile_ssh_session_error1  (FUNC_NAME, session, channel);
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_request_pty, "channel-request-pty", 1, 0, 0,
            (SCM channel),
            "\
Request a PTY (pseudo terminal).\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_request_pty
{
  struct channel_data *data = _scm_to_channel_data (channel);
  int res;

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);

  res = ssh_channel_request_pty (data->ssh_channel);
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (data->ssh_channel);
      guile_ssh_session_error1  (FUNC_NAME, session, channel);
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_request_shell, "channel-request-shell", 1, 0, 0,
            (SCM channel),
            "\
Request a shell.\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_request_shell
{
  struct channel_data *data = _scm_to_channel_data (channel);
  int res;

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);

  res = ssh_channel_request_shell (data->ssh_channel);
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (data->ssh_channel);
      guile_ssh_session_error1 (FUNC_NAME, session, channel);
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

/* Set an environment variable NAME to value VALUE
   Return value is undefined. */
SCM_DEFINE (guile_ssh_channel_request_env, "channel-request-env", 3, 0, 0,
            (SCM channel, SCM name, SCM value),
            "\
Set an environment variable NAME to value VALUE.\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_request_env
{
  struct channel_data *data = _scm_to_channel_data (channel);
  char *c_name;
  char *c_value;
  int res;

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT (scm_is_string (name), name, SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_string (value), value, SCM_ARG3, FUNC_NAME);

  c_name  = scm_to_locale_string (name);
  c_value = scm_to_locale_string (value);
  res = ssh_channel_request_env (data->ssh_channel, c_name, c_value);
  if (res != SSH_OK)
    {
      ssh_session session = ssh_channel_get_session (data->ssh_channel);
      guile_ssh_session_error1 (FUNC_NAME, session, channel);
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

/* Asserts:
   - RES is one of the valid contants described in 'libssh.h'.
 */
SCM
_ssh_result_to_symbol (int res)
{
  switch (res)
    {
    case SSH_OK:
      return scm_from_locale_symbol ("ok");
    case SSH_AGAIN:
      return scm_from_locale_symbol ("again");
    case SSH_ERROR:
      return scm_from_locale_symbol ("error");

    default:                    /* Must not happen. */
      assert (0);
      return SCM_BOOL_F;
    }
}

SCM_GSSH_DEFINE (guile_ssh_channel_open_forward,
                 "%channel-open-forward", 5,
                 (SCM channel, SCM remote_host, SCM remote_port,
                  SCM source_host, SCM local_port))
#define FUNC_NAME s_guile_ssh_channel_open_forward
{
  struct channel_data *cd = _scm_to_channel_data (channel);
  char *c_remote_host = NULL;
  char *c_source_host = NULL;
  int res;

  SCM_ASSERT (scm_is_string (remote_host), remote_host, SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_number (remote_port), remote_port, SCM_ARG3, FUNC_NAME);
  SCM_ASSERT (scm_is_string (source_host), source_host, SCM_ARG4, FUNC_NAME);
  SCM_ASSERT (scm_is_number (local_port),  local_port,  SCM_ARG5, FUNC_NAME);

  scm_dynwind_begin (0);

  c_remote_host = scm_to_locale_string (remote_host);
  scm_dynwind_free (c_remote_host);

  c_source_host = scm_to_locale_string (source_host);
  scm_dynwind_free (c_source_host);

  res = ssh_channel_open_forward (cd->ssh_channel,
                                  c_remote_host, scm_to_int32 (remote_port),
                                  c_source_host, scm_to_int32 (local_port));

  if (res == SSH_OK)
    SCM_SET_CELL_TYPE (channel, SCM_CELL_TYPE (channel) | SCM_OPN);

  scm_dynwind_end ();

  return _ssh_result_to_symbol (res);
}
#undef FUNC_NAME

SCM_GSSH_DEFINE (guile_ssh_channel_listen_forward,
                 "%channel-listen-forward", 3,
                 (SCM session, SCM address, SCM port))
#define FUNC_NAME s_guile_ssh_channel_listen_forward
{
  struct session_data *sd = _scm_to_session_data (session);
  char *c_address = NULL;
  int bound_port;
  int res;

  SCM_ASSERT (scm_is_string (address) || scm_is_bool (address),
              address, SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_number (port), port, SCM_ARG3, FUNC_NAME);

  scm_dynwind_begin (0);

  if (scm_is_string (address))
    {
      c_address = scm_to_locale_string (address);
      scm_dynwind_free (c_address);
    }

  res = ssh_forward_listen (sd->ssh_session,
                            c_address,
                            scm_to_int (port),
                            &bound_port);
  if (res != SSH_OK)
    bound_port = -1;
  else if (scm_zero_p (port))
    bound_port = scm_to_int (port);

  scm_dynwind_end ();

  return scm_values (scm_list_2 (_ssh_result_to_symbol (res),
                                 scm_from_int (bound_port)));
}
#undef FUNC_NAME

SCM_GSSH_DEFINE (guile_ssh_channel_accept_forward,
                 "%channel-accept-forward", 2,
                 (SCM session, SCM timeout))
#define FUNC_NAME s_guile_ssh_channel_accept_forward
{
  struct session_data *sd = _scm_to_session_data (session);
  ssh_channel c_channel = NULL;
  SCM channel = SCM_BOOL_F;
  int port;

  SCM_ASSERT (scm_is_number (timeout), timeout, SCM_ARG2, FUNC_NAME);

  c_channel = ssh_channel_accept_forward (sd->ssh_session,
                                          scm_to_int (timeout),
                                          &port);
  if (c_channel)
    {
      channel = _scm_from_channel_data (c_channel, session,
                                        SCM_RDNG | SCM_WRTNG);
      SCM_SET_CELL_TYPE (channel, SCM_CELL_TYPE (channel) | SCM_OPN);
    }

  return scm_values (scm_list_2 (channel, scm_from_int (port)));
}
#undef FUNC_NAME

/* FIXME: Should it be defined in some other module? */
SCM_GSSH_DEFINE (guile_ssh_channel_cancel_forward,
                 "channel-cancel-forward", 3,
                 (SCM session, SCM address, SCM port))
#define FUNC_NAME s_guile_ssh_channel_cancel_forward
{
  struct session_data *sd = _scm_to_session_data (session);
  char *c_address = NULL;
  int res;

  SCM_ASSERT (scm_is_string (address), address, SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_number (port),    port,    SCM_ARG3, FUNC_NAME);

  scm_dynwind_begin (0);

  c_address = scm_to_locale_string (address);
  scm_dynwind_free (c_address);

  res = ssh_forward_cancel (sd->ssh_session,
                            c_address, scm_to_int32 (port));

  scm_dynwind_end ();

  return _ssh_result_to_symbol (res);
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_set_pty_size_x,
            "channel-set-pty-size!", 3, 0, 0,
            (SCM channel, SCM col, SCM row),
            "\
Change size of the PTY to columns COL and rows ROW.\n\
eturn value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_set_pty_size_x
{
  struct channel_data *data = _scm_to_channel_data (channel);

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT (scm_is_unsigned_integer (col, 0, UINT32_MAX), col,
              SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_unsigned_integer (row, 0, UINT32_MAX), row,
              SCM_ARG2, FUNC_NAME);

  ssh_channel_change_pty_size (data->ssh_channel,
                               scm_to_uint32 (col),
                               scm_to_uint32 (row));

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_set_stream_x,
            "channel-set-stream!", 2, 0, 0,
            (SCM channel, SCM stream_name),
            "\
Set stream STREAM_NAME for channel CHANNEL.  STREAM_NAME must be one of the \n\
following symbols: \"stdout\" (default), \"stderr\".\n\
Return value is undefined.\
")
#define FUNC_NAME s_guile_ssh_channel_set_stream_x
{
  struct channel_data *cd = _scm_to_channel_data (channel);

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT (scm_is_symbol (stream_name), stream_name, SCM_ARG2, FUNC_NAME);

  if (scm_is_eq (stream_name, scm_from_locale_symbol ("stdout")))
    {
      cd->is_stderr = 0;
    }
  else if (scm_is_eq (stream_name, scm_from_locale_symbol ("stderr")))
    {
      cd->is_stderr = 1;
    }
  else
    {
      guile_ssh_error1 (FUNC_NAME,
                        "Wrong stream name.  Possible names are: "
                        "'stdout, 'stderr", stream_name);
    }

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_GSSH_DEFINE (gssh_channel_stream, "%gssh-channel-stream", 1,
                 (SCM channel))
#define FUNC_NAME s_gssh_channel_stream
{
  struct channel_data *cd = _scm_to_channel_data (channel);

  GSSH_VALIDATE_OPEN_CHANNEL (channel, SCM_ARG1, FUNC_NAME);

  if (cd->is_stderr == 0)
    return scm_from_locale_symbol ("stdout");
  if (cd->is_stderr == 1)
    return scm_from_locale_symbol ("stderr");

  guile_ssh_error1 (FUNC_NAME, "Wrong stream.",
                    scm_from_int (cd->is_stderr));

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_GSSH_DEFINE (gssh_channel_session, "%gssh-channel-session", 1,
                 (SCM channel))
#define FUNC_NAME s_gssh_channel_session
{
  struct channel_data *cd = _scm_to_channel_data (channel);
  GSSH_VALIDATE_CHANNEL_DATA (cd, channel, FUNC_NAME);
  return cd->session;
}
#undef FUNC_NAME


/* Predicates */

SCM_DEFINE (guile_ssh_channel_is_open_p, "channel-open?", 1, 0, 0,
            (SCM channel),
            "Return #t if channel CHANNEL is open, #f otherwise.")
{
  struct channel_data *data = _scm_to_channel_data (channel);
  if (data && ssh_channel_is_open (data->ssh_channel))
    return SCM_BOOL_T;
  return SCM_BOOL_F;
}

SCM_GSSH_DEFINE (gssh_channel_send_eof, "%channel-send-eof",
                 1, (SCM channel))
#define FUNC_NAME s_gssh_channel_send_eof
{
  struct channel_data *cd = _scm_to_channel_data (channel);
  scm_t_bits pt_bits;
  int rc;

  GSSH_VALIDATE_CHANNEL_DATA (cd, channel, FUNC_NAME);

  pt_bits = SCM_CELL_TYPE (channel);
  if ((pt_bits & SCM_WRTNG) == 0)
    {
      guile_ssh_error1 (FUNC_NAME, "Could not send EOF on an input channel",
                        channel);
    }

  rc = ssh_channel_send_eof (cd->ssh_channel);
  if (rc == SSH_ERROR)
    guile_ssh_error1 (FUNC_NAME, "Could not send EOF on a channel", channel);

  SCM_SET_CELL_TYPE (channel, pt_bits & ~SCM_WRTNG);

  return SCM_UNDEFINED;
}
#undef FUNC_NAME

SCM_DEFINE (guile_ssh_channel_is_eof_p, "channel-eof?", 1, 0, 0,
            (SCM channel),
            "\
Return #t if remote has set EOF, #f otherwise.\n\
Throw `guile-ssh-error' if the channel has been closed and freed.\
")
#define FUNC_NAME s_guile_ssh_channel_is_eof_p
{
  struct channel_data *data = _scm_to_channel_data (channel);
  GSSH_VALIDATE_CHANNEL_DATA (data, channel, FUNC_NAME);
  return scm_from_bool (ssh_channel_is_eof (data->ssh_channel));
}
#undef FUNC_NAME


/* Initialize channel related functions. */
void
init_channel_func (void)
{
#include "channel-func.x"
}

/* channel-func.c ends here */
