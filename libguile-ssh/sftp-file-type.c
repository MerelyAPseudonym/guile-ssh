/* sftp-file-type.c -- SFTP file type.
 *
 * Copyright (C) 2015 Artyom V. Poptsov <poptsov.artyom@gmail.com>
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

#include <libguile.h>
#include <libssh/libssh.h>

#include "common.h"
#include "sftp-session-type.h"
#include "sftp-file-type.h"


scm_t_bits sftp_file_tag;       /* Smob tag. */


enum {
  DEFAULT_PORT_R_BUFSZ = 256,      /* Default read buffer size */
  DEFAULT_PORT_W_BUFSZ = 1         /* Default write buffer size */
};


/* Ptob callbacks. */

/* Read data from the channel.  Return EOF if no data is available or
   throw `guile-ssh-error' if an error occured. */
static int
ptob_fill_input (SCM file)
#define FUNC_NAME "ptob_fill_input"
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (file);
  scm_port *pt = SCM_PTAB_ENTRY (file);
  ssize_t res;

  res = sftp_read (fd->file, pt->read_buf, pt->read_buf_size);
  if (! res)
    return EOF;
  else if (res < 0)
    guile_ssh_error1 (FUNC_NAME, "Error reading the file", file);

  pt->read_pos = pt->read_buf;
  pt->read_end = pt->read_buf + res;

  return *pt->read_buf;
}
#undef FUNC_NAME

static void
ptob_write (SCM file, const void* data, size_t sz)
#define FUNC_NAME "ptob_write"
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (file);
  ssize_t nwritten = sftp_write (fd->file, data, sz);
  if (nwritten != sz)
    guile_ssh_error1 (FUNC_NAME, "Error writing the file", file);
}
#undef FUNC_NAME

static int
ptob_input_waiting (SCM file)
#define FUNC_NAME "ptob_input_waiting"
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (file);
  sftp_attributes attr = sftp_fstat (fd->file);
  uint64_t pos = sftp_tell64 (fd->file);
  return attr->size - pos;
}
#undef FUNC_NAME


SCM_DEFINE (gssh_open_file, "%gssh-sftp-open-file", 4, 0, 0,
            (SCM sftp_session, SCM path, SCM access_type, SCM mode),
            "")
#define FUNC_NAME s_gssh_open_file
{
  struct sftp_session_data *sftp_sd = _scm_to_sftp_session_data (sftp_session);
  sftp_file file;
  char* c_path;
  int c_access_type;
  mode_t c_mode;

  SCM_ASSERT (scm_is_string (path), path, SCM_ARG2, FUNC_NAME);
  SCM_ASSERT (scm_is_number (access_type), access_type, SCM_ARG3, FUNC_NAME);
  SCM_ASSERT (scm_is_number (mode), mode, SCM_ARG4, FUNC_NAME);

  scm_dynwind_begin (0);

  c_path = scm_to_locale_string (path);
  scm_dynwind_free (c_path);

  c_access_type = scm_to_uint (access_type);
  c_mode = scm_to_uint (mode);

  file = sftp_open (sftp_sd->sftp_session, c_path, c_access_type, c_mode);
  if (file == NULL)
    {
      guile_ssh_error1 (FUNC_NAME, "Could not open a file",
                        scm_list_4 (sftp_session, path, access_type, mode));
    }

  scm_dynwind_end ();
  return _scm_from_sftp_file (file, path, sftp_session);
}
#undef FUNC_NAME

SCM_DEFINE (gssh_sftp_session_p, "%gssh-sftp-file?", 1, 0, 0, (SCM x), "")
{
  return scm_from_bool (SCM_SMOB_PREDICATE (sftp_file_tag, x));
}

/* Complete the processing of buffered output data.  Currently this
   callback makes no effect because the channel CHANNEL uses
   unbuffered output. */
static void
ptob_flush (SCM sftp_file)
#define FUNC_NAME "ptob_flush"
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (sftp_file);
  scm_port *pt = SCM_PTAB_ENTRY (sftp_file);
  size_t wrsize = pt->write_pos - pt->write_buf;

  if (wrsize)
    ptob_write (sftp_file, pt->write_buf, wrsize);

  pt->write_pos = pt->write_buf;
}
#undef FUNC_NAME

static int
ptob_close (SCM sftp_file)
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (sftp_file);
  scm_port *pt = SCM_PTAB_ENTRY (sftp_file);

  ptob_flush (sftp_file);

  if (fd)
    {
      sftp_close (fd->file);
    }

  scm_gc_free (fd, sizeof (struct sftp_file_data), "sftp file");
  scm_gc_free (pt->write_buf, pt->write_buf_size, "port write buffer");
  scm_gc_free (pt->read_buf,  pt->read_buf_size, "port read buffer");
  SCM_SETSTREAM (sftp_file, NULL);
}

static SCM
mark_sftp_file (SCM sftp_file)
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (sftp_file);
  return fd->sftp_session;
}

static size_t
free_sftp_file (SCM sftp_file)
{
  return 0;
}

static SCM
equalp_sftp_file (SCM x1, SCM x2)
{
  struct sftp_file_data *fd1 = _scm_to_sftp_file_data (x1);
  struct sftp_file_data *fd2 = _scm_to_sftp_file_data (x2);

  if ((! fd1) || (! fd2))
    return SCM_BOOL_F;
  else if (fd1 != fd2)
    return SCM_BOOL_F;
  else
    return SCM_BOOL_T;
}

static int
print_sftp_file (SCM sftp_file, SCM port, scm_print_state *pstate)
{
  struct sftp_file_data *fd = _scm_to_sftp_file_data (sftp_file);
  ssh_session session = fd->file->sftp->session;
  sftp_attributes attr = sftp_fstat (fd->file);
  char *user = NULL;
  char *host = NULL;
  unsigned int ssh_port;
  int res;

  scm_puts ("#<sftp-file ", port);

  res = ssh_options_get (session, SSH_OPTIONS_USER, &user);
  scm_display ((res == SSH_OK) ? scm_from_locale_string (user) : SCM_UNDEFINED,
               port);
  ssh_string_free_char (user);

  scm_putc ('@', port);

  res = ssh_options_get (session, SSH_OPTIONS_HOST, &host);
  scm_display ((res == SSH_OK) ? scm_from_locale_string (host) : SCM_UNDEFINED,
               port);
  ssh_string_free_char (host);

  scm_putc (':', port);
  res = ssh_options_get_port (session, &ssh_port);
  scm_display ((res == SSH_OK) ? scm_from_int (ssh_port) : SCM_UNDEFINED,
               port);
  scm_putc (' ', port);

  scm_display (SCM_FILENAME (sftp_file), port);

  scm_putc (' ', port);

  scm_display (_scm_object_hex_address (sftp_file), port);
  scm_puts (">", port);
  return 1;
}


/* Convert SCM object X to a SFTP file data object. */
struct sftp_file_data *
_scm_to_sftp_file_data (SCM x)
{
  scm_assert_smob_type (sftp_file_tag, x);
  return SCM_PTAB_ENTRY (x)
    ? (struct sftp_file_data *) SCM_STREAM (x)
    : (struct sftp_file_data *) NULL;
}

/* Convert SFTP file FD to a SCM object; set SFTP_SESSION as a parent of the
   object. */
SCM
_scm_from_sftp_file (const sftp_file file, const SCM name, SCM sftp_session)
{
  SCM ptob;
  scm_port *pt;
  struct sftp_file_data *fd = scm_gc_malloc (sizeof (struct sftp_file_data),
                                             "sftp file");
  fd->sftp_session = sftp_session;
  fd->file         = file;
  ptob = scm_new_port_table_entry (sftp_file_tag);
  pt   = SCM_PTAB_ENTRY (ptob);
  pt->rw_random = 0;

  /* Output init */
  pt->write_buf_size = DEFAULT_PORT_R_BUFSZ;
  pt->write_buf = scm_gc_malloc (pt->write_buf_size, "port write buffer");
  pt->write_pos = pt->write_end = pt->write_buf;

  /* Input init */
  pt->read_buf_size = DEFAULT_PORT_W_BUFSZ;
  pt->read_buf = scm_gc_malloc (pt->read_buf_size, "port read buffer");
  pt->read_pos = pt->read_end = pt->read_buf;

  SCM_SET_FILENAME (ptob, name);
  SCM_SET_CELL_TYPE (ptob, sftp_file_tag | SCM_RDNG | SCM_WRTNG | SCM_OPN);
  SCM_SETSTREAM (ptob, fd);

  return ptob;
}


/* Ptob initialization. */
void
init_sftp_file_type (void)
{
  sftp_file_tag = scm_make_port_type ("sftp-file",
                                      &ptob_fill_input,
                                      &ptob_write);
  scm_set_port_close (sftp_file_tag, ptob_close);
  scm_set_port_flush (sftp_file_tag, ptob_flush);
  scm_set_port_input_waiting (sftp_file_tag, ptob_input_waiting);
  scm_set_port_mark (sftp_file_tag, mark_sftp_file);
  scm_set_port_free (sftp_file_tag, free_sftp_file);
  scm_set_port_print (sftp_file_tag, print_sftp_file);
  scm_set_port_equalp (sftp_file_tag, equalp_sftp_file);

#include "sftp-file-type.x"
}

/* sftp-file-type.c ends here. */