#!/bin/env python2.7
'''
Staging Server Transfer Script

A xfer script executed from a code staging server.
'''

# ----- Python Library Imports -----

import argparse
import ast
import ConfigParser
import glob
import json
import logging
import os
import shutil
import socket
import string
import subprocess
import sys

# ----------------------------------



# --------- Initialization ---------

HELP_DESCRIPTION = """
A (post-)xfer script executed on each cluster's respective staging servers. 
"""

HELP_EPILOG = """
examples:
  xfer-staging.py foo
    Executes the target specification named "foo" within the inherited environment.
"""

# ------------------------------------



# ----------- Email Bodies -----------

PRE_BAD_MSG = 'The staging transfer script reports that it was unable to'

CMD_EC = """
The staging transfer script reports that it encountered a non-zero exit code
from executing an arbitrary local command.
"""

CMD_EX = """
The staging transfer script reports that it encountered an exception while
executing an arbitrary local command.
"""

CONFIG_BAD_TARGET = """
The staging transfer script reports that it was given an invalid (missing) target
specification for the given configuration environment.
"""

CONFIG_CANT_PARSE = """
{pre} correctly parse the specified configuration file.
""".format(pre=PRE_BAD_MSG)

CONFIG_CANT_PARSE_CMD = """
{pre} correctly parse the arbitrary command specification defined in the specified configuration target.
""".format(pre=PRE_BAD_MSG)

CONFIG_CANT_PARSE_ENV = """
{pre} correctly parse the environment specification defined in the specified
configuration file.
""".format(pre=PRE_BAD_MSG)

CONFIG_CANT_PARSE_FLYWAY = """
{pre} correctly parse the flyway specification defined in the specified configuration target.
""".format(pre=PRE_BAD_MSG)

CONFIG_CANT_PARSE_RSYNC = """
{pre} correctly parse the rsync specification defined in the specified configuration target.
""".format(pre=PRE_BAD_MSG)

CONFIG_FILE_DOESNT_EXIST = """
{pre} verify the existence of the specified deployment configuration file.
""".format(pre=PRE_BAD_MSG)

CONFIG_MISSING_ENV = """
{pre} validate the specified configuration file because of a missing environment
specification within the "global" section.
""".format(pre=PRE_BAD_MSG)

CONFIG_MISSING_GLOBAL = """
{pre} validate the specified configuration file because of a missing "global" section.
""".format(pre=PRE_BAD_MSG)

CONFIG_NO_METHOD = """
The staging transfer script reports that no transfer methods were define in the
specified configuration target.
"""

DONE = """
The staging transfer script reports that it has completed the transfer process.
"""

FLYWAY_CONFIG_MISSING = """
The staging transfer script reports that the specified flyway configuration file
does not exist.
"""

FLYWAY_DB_MISSING = """
{pre} handle the database migration specification for the specified host because
of a missing "database" definition.
""".format(pre=PRE_BAD_MSG)

FLYWAY_EXCEPTION = """
The staging transfer script reports that it encountered an exception while
performing a database migration.
"""

FLYWAY_EXEC_MISSING = """
The staging transfer script reports that the specified flyway executable does
not exist.
"""

FLYWAY_EXIT_CODE = """
The staging transfer script reports that it encountered a non-zero exit code while
performing a database migration.
"""

FLYWAY_SERVER_MISSING = """
{pre} handle the database migration specification because of a missing "server" definition.
""".format(pre=PRE_BAD_MSG)

FLYWAY_SOURCE_MISSING = """
{pre} handle the database migration specification for the specified host because
of a missing "source" definition.
""".format(pre=PRE_BAD_MSG)

HOSTNAME_NOT_IN_ENV = """
{pre} find an environment mapping for the hostname of the executing machine
in the specified configuration file.
""".format(pre=PRE_BAD_MSG)

LC_BAD_GLOB = """
{pre} handle the local file copy specification because of the source glob not
matching any existing files or directories.
""".format(pre=PRE_BAD_MSG)

LC_COPY_EXCEPTION = """
The staging transfer script reports that it encountered an exception while
trying to perform the local copy specification for one of the specified source files/directories.
"""

LC_DST_EXCEPTION = """
The staging transfer script reports that it encountered an exception while
trying to create the target directory specified in the local file copy specification.
"""

LC_MULTI_DST = """
{pre} handle the local file copy specification because of multiple source files
destined to the same target file.
""".format(pre=PRE_BAD_MSG)

LC_SRC_MISSING = """
The staging transfer script reports that one or more of the source paths of the
defined local copy specification do not exist on the local filesystem.
"""

FLYWAY_SOURCE_DOESNT_EXIST = """
{pre} handle the database migration specification for the specified host because
of the specified source defintion not existing on the filesystem.
""".format(pre=PRE_BAD_MSG)

RSYNC_DESTINATION_MISSING = """
{pre} handle the rsync specification for the specified host because of a missing
"destination" definition.
""".format(pre=PRE_BAD_MSG)

RSYNC_EXEC_MISSING = """
The staging transfer script reports that the specified rsync executable does
not exist.
"""

RSYNC_EXCEPTION = """
The staging transfer script reports that it encountered an exception while trying
to rsync to the specified host.
"""

RSYNC_EXIT_CODE = """
The staging transfer script reports that it encountered a non-zero exit code
while trying to rsync to the specified host.
"""

RSYNC_SOURCE_MISSING = """
{pre} handle the rsync specification for the specified host because of a missing
"source" definition.
""".format(pre=PRE_BAD_MSG)

RSYNC_SOURCE_DOESNT_EXIST = """
{pre} handle the rsync specification for the specified host because of a
non-existent source directory.
""".format(pre=PRE_BAD_MSG)

# ------------------------------------



# --------- Private Functions --------

def _flyway(src, dst_server, dst_db, flyway_args=''):
    '''
    Performs a mysql migration using the flyway utility.
    If the script is run in dry-run mode, the flyway utility will be run
    with the "info" command.
    '''
    if args.dry_run:
        flyway_command = 'info'
    else:
        flyway_command = 'migrate'
    flyway_config = '-configFile=' + args.flyway_config
    flyway_source = '-locations=filesystem:' + src
    if not args.flyway_callbacks:
        flyway_callbacks = ' '
    else:
        flyway_callbacks = ' -callbacks={cb} '.format(cb=args.flyway_callbacks)
    flyway_dst = '-url=jdbc:mysql://{server}/{db}'.format(
        server = dst_server,
        db = dst_db
    )
    cmd = '{flyway_exec} {config} {source} {args}{callbacks}{dst} {command}'.format(
        flyway_exec = args.flyway_executable,
        config = flyway_config,
        source = flyway_source,
        args = flyway_args,
        callbacks = flyway_callbacks,
        dst = flyway_dst,
        command = flyway_command
    )
    return _run_process(cmd)


def _rsync(src, dst_server, dst_path, rsync_args=''):
    '''
    Performs an rsync from the specified source path to the specified
    destination server, path.
    '''
    if args.dry_run:
        true_rsync_args = rsync_args + ' --dry-run'
    else:
        true_rsync_args = rsync_args
    dst = 'rsync://{server}/{dst_path}'.format(
        server = dst_server,
        dst_path = dst_path.lstrip('/')
    )
    cmd = '{rsync_exec} {args} {src} {dst}'.format(
        rsync_exec = args.rsync_executable,
        args = true_rsync_args,
        src = src,
        dst = dst
    )
    return _run_process(cmd)


def _run_process(cmd):
    '''
    Runs the specified command as a subprocess, returning the output of the
    command (split by lines) and its exit code.
    '''
    process = subprocess.Popen(
        cmd,
        stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT,
        shell = True
    )
    output = process.communicate()[0].splitlines()
    exit_code = process.returncode
    return (output, exit_code)


def _send_email(subject, body, level='error'):
    '''
    Sends an email to the configured recipients with the specified body, subject,
    and alert level. Whether the email actually gets sent is dependent on the
    alert level specified by "args.email_level".
    '''
    if not level in ['error', 'warning', 'info']:
        raise Exception('Invalid email level: "' + str(level) + '"')
    if args.email_level == 'never' or (args.email_level == 'error' and level in ['warning', 'info']) or (args.email_level == 'warning' and level == 'info'):
        return
    else:
        if level == 'error':
            full_subject = 'ERROR: ' + subject
            full_body = body + '\n\nSee "' + args.log_file + '" on the machine for more details.'
        elif level == 'warning':
            full_subject = 'WARNING: ' + subject
            full_body = body + '\n\nSee "' + args.log_file + '" on the machine for more details.'
        else:
            full_subject = subject
            full_body = body
        with open('/tmp/xfer-staging.email', 'w') as f:
            f.write('To: ' + args.email_to + '\n')
            f.write('Subject: ' + full_subject + '\n\n')
            f.write(full_body)
        with open(os.devnull, 'w') as DEVNULL:
            email_exit_code = subprocess.call('cat /tmp/xfer-staging.email | /usr/sbin/sendmail -t', shell=True, stdout=DEVNULL, stderr=subprocess.STDOUT)
        if email_exit_code != 0:
            raise Exception('sendmail subprocess call returned non-zero exit code')
        else:
            return

# ------------------------------------



# --------- Public Functions ---------

def handle_cmd(cmd_spec):
    '''
    Handles local arbitrary command execution.
    '''
    error_pre = 'Unable to handle arbitrary command specification'
    for cmd_template in cmd_spec:
        logging.debug('RAW CMD: ' + cmd_template)
        cmd = string.Template(cmd_template).safe_substitute(global_settings)
        logging.info('Executing "{cmd}"...').format(cmd=cmd)
        try:
            (cmd_output, cmd_ec) = _run_process(cmd)
        except Exception as e:
            logging.critical('Unable to execute arbitrary command - ' + str(e) + '.')
            send_email(
                error_pre,
                CMD_EX,
                'error'
            )
            exit(1)
        logging.debug('EXIT CODE: ' + str(cmd_ec))
        if cmd_ec != 0:
            if cmd_output:
                for l in cmd_output:
                    logging.critical('OUTPUT: ' + l)
            logging.critical(
                'Unable to execute arbitrary command - process returned non-zero exit code.'
            )
            send_email(
                error_pre,
                CMD_EC,
                'error'
            )
            exit(1)
        else:
            if cmd_output:
                for l in cmd_output:
                    logging.debug('OUTPUT: ' + l)
        

def handle_flyway(flyway_spec):
    '''
    Handles mysql migrations via the flyway utility.
    '''
    logging.debug('CONFIGURATION FILE: ' + args.flyway_config)
    logging.debug('CALLBACKS: ' + args.flyway_callbacks)
    logging.debug('EXECUTABLE: ' + args.flyway_executable)
    error_pre = 'Unable to handle flyway specification'
    for migration in flyway_spec:
        if not 'args' in migration:
            logging.debug('No additional flyway arguments specified for migration.')
            mig_args = ''
        else:
            mig_args = string.Template(migration['args']).safe_substitute(global_settings)
            logging.debug('ARGS: ' + mig_args)
        if not 'source' in migration:
            logging.critical(
                '{pre} - migration source not specified.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                FLYWAY_SOURCE_MISSING,
                'error'
            )
            exit(1)
        else:
            mig_src = string.Template(migration['source']).safe_substitute(global_settings)
            logging.debug('SOURCE: ' + mig_src)
        if not os.path.exists(mig_src):
            logging.critical(
                '{pre} - migration source path does not exist.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                FLYWAY_SOURCE_DOESNT_EXIST,
                'error'
            )
            exit(1)
        if not 'server' in migration:
            logging.critical(
                '{pre} - migration destination server not specified.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                FLYWAY_SERVER_MISSING,
                'error'
            )
            exit(1)
        else:
            mig_server = string.Template(migration['server']).safe_substitute(global_settings)
            logging.debug('SERVER: ' + mig_server)
        if not 'database' in migration:
            logging.critical(
                '{pre} - migration destination database not specified.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                FLYWAY_DB_MISSING,
                'error'
            )
            exit(1)
        else:
            mig_db = string.Template(migration['database']).safe_substitute(global_settings)
            logging.debug('DATABASE: ' + mig_db)
        logging.info(
            'Migrating {db} on {server}...'.format(db=mig_db, server=mig_server)
        )
        try:
            (mig_output, mig_ec) = _flyway(
                src = mig_src,
                dst_server = mig_server,
                dst_db = mig_db,
                flyway_args = mig_args
            )
        except Exception as e:
            logging.critical('Unable to perform database migration - ' + str(e) + '.')
            send_email(
                'Unable to perform database migration',
                FLYWAY_EXCEPTION,
                'error'
            )
            exit(1)
        logging.debug('EXIT CODE: ' + str(mig_ec))
        if mig_ec != 0:
            if mig_output:
                for l in mig_output:
                    logging.critical('OUTPUT: ' + l)
            logging.critical(
                'Unable to perform database migration - flyway process returned non-zero exit code.'
            )
            send_email(
                'Unable to perform database migration',
                FLYWAY_EXIT_CODE,
                'error'
            )
            exit(1)
        else:
            if mig_output:
                for l in mig_output:
                    logging.debug('OUTPUT: ' + l)


def handle_local_copy(local_copy_spec):
    '''
    Handles a local_copy definition in the specified configuration target.
    '''
    error_pre = 'Unable to handle local file copy specification'
    for src, dst in local_copy_spec.iteritems():
        logging.debug('SOURCE: ' + src)
        logging.debug('DESTINATION: ' + dst)
        if '*' in src:
            logging.debug('Expanding source globs...')
            src_list = glob.glob(os.path.expandvars(os.path.expanduser(src)))
            if not src_list:
                logging.critical(
                    '{pre} - source glob expansion did match any files.'.format(pre=error_pre)
                )
                send_email(
                    error_pre,
                    LC_BAD_GLOB,
                    'error'
                )
                exit(1)
        else:
            logging.debug('No globs detected in source definition.')
            src_list = [os.path.expandvars(os.path.expanduser(src))]
        dst_expanded = os.path.expandvars(os.path.expanduser(dst))
        if os.path.isdir(dst_expanded):
            logging.debug('Destination directory already exists.')
        elif os.path.isfile(dst_expanded):
            if len(src_list) > 1:
                logging.critical(
                    '{pre} - multiple source files destined to same target file.'.format(pre=error_pre)
                )
                send_email(
                    error_pre,
                    LC_MULTI_DST,
                    'error'
                )
                exit(1)
            else:
                logging.debug('Destination file already exists - file will be overwritten.')
        else:
            logging.debug('Destination directory does not exist.')
            logging.debug('Creating destination directory...')
            try:
                if args.dry_run:
                    logging.debug('Destination directory not created - dry-run mode enabled.')
                else:
                    os.makedirs(dst_expanded)
            except Exception as e:
                logging.critical(
                    '{pre} - unable to create destination directory - {e}.'.format(pre=error_pre, e=str(e))
                )
                send_email(
                    error_pre,
                    LC_DST_EXCEPTION,
                    'error'
                )
                exit(1)
        for path in src_list:
            logging.info(
                'Copying "{src}" to "{dst}"...'.format(src=path,dst=dst_expanded)
            )
            if not os.path.exists(path):
                logging.critical(
                    '{pre} - specified source path does not exist.'
                )
                send_email(
                    error_pre,
                    LC_SRC_MISSING,
                    'error'
                )
                exit(1)
            try:
                if args.dry_run:
                    logging.debug('No copy action taken - dry-run mode enabled.')
                else:
                    if os.path.isfile(path):
                        shutil.copy(path, dst_expanded)
                    else:
                        shutil.copytree(path, dst_expanded)
            except Exception as e:
                logging.critical(
                    '{pre} - unable to copy source to destination - {e}.'.format(pre=error_pre, e=str(e))
                )
                send_email(
                    error_pre,
                    LC_COPY_EXCEPTION,
                    'error'
                )
                exit(1)


def handle_rsync(rsync_spec):
    '''
    Handles an rsync definition in the specified configuration target.
    '''
    logging.debug('EXECUTABLE: ' + args.rsync_executable)
    for host, spec in rsync_spec.iteritems():
        error_pre = 'Unable to handle rsync specification for host "{host}"'.format(host=host)
        if 'args' in spec:
            rsync_args = string.Template(spec['args']).safe_substitute(global_settings)
            logging.debug('ARGS: {args}'.format(args=rsync_args))
        else:
            logging.debug('No rsync arguments specified for "{host}".'.format(host=host))
            rsync_args = ''
        if not 'source' in spec:
            logging.critical(
                '{pre} - rsync source not specified.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                RSYNC_SOURCE_MISSING,
                'error'
            )
            exit(1)
        rsync_src = string.Template(spec['source']).safe_substitute(global_settings)
        logging.debug('SOURCE: {src}'.format(src=rsync_src))
        if not os.path.exists(rsync_src):
            logging.critical(
                '{pre} - specified rsync source does not exist.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                RSYNC_SOURCE_DOESNT_EXIST,
                'error'
            )
            exit(1)
        if not 'destination' in spec:
            logging.critical(
                '{pre} - rsync destination not specified.'.format(pre=error_pre)
            )
            send_email(
                error_pre,
                RSYNC_DESTINATION_MISSING,
                'error'
            )
            exit(1)
        rsync_dst = string.Template(spec['destination']).safe_substitute(global_settings)
        logging.debug('DESTINATION: {dst}'.format(dst=rsync_dst))
        logging.info('Deploying to {host}...'.format(host=host))
        try:
            (rsync_output, rsync_exit_code) = _rsync(
                src = rsync_src,
                dst_server = host,
                dst_path = rsync_dst,
                rsync_args = rsync_args
            )
        except Exception as e:
            logging.critical(
                'Unable to rsync to specified host - {e}.'.format(e=str(e))
            )
            send_email(
                'Unable to rsync to specified host ({host})'.format(host=host),
                RSYNC_EXCEPTION,
                'error'
            )
            exit(1)
        logging.debug('EXIT CODE: ' + str(rsync_exit_code))
        if rsync_exit_code != 0:
            if rsync_output:
                for l in rsync_output:
                    logging.critical('OUTPUT: ' + l)
            logging.critical(
                'Unable to rsync to specified host - rsync process returned non-zero exit code.'
            )
            send_email(
                'Unable to rsync to specified host ({host})'.format(host=host),
                RSYNC_EXIT_CODE,
                'error'
            )
            exit(1)
        else:
            if rsync_output:
                for l in rsync_output:
                    logging.debug('OUTPUT: ' + l)
        

def main():
    '''
    The main entry point of the script.
    '''
    # Parse command-line arguments
    parse_arguments()

    # Setup logging
    try:
        if args.log_mode == 'append':
            logging_fmode = 'a'
        else:
            logging_fmode = 'w'
        if args.log_level == 'info':
            logging_level = logging.INFO
        else:
            logging_level = logging.DEBUG
        logging.basicConfig(
            filename = args.log_file,
            filemode = logging_fmode,
            level = logging_level,
            format = '[%(levelname)s] [%(asctime)s] [%(process)d] [%(module)s.%(funcName)s] %(message)s',
            datefmt = '%m/%d/%Y %I:%M:%S %p'
        )
        logging.addLevelName(logging.CRITICAL, 'CRIT')
        logging.addLevelName(logging.WARNING, 'WARN')
        logging.addLevelName(logging.DEBUG, 'DEBG')
    except Exception as e:
        exit('Unable to initialize logging system - ' + str(e) + '.')

    # Get the hostname of the machine
    logging.debug('Getting hostname...')
    try:
        global hostname
        hostname = socket.gethostname().split('.', 1)[0]
    except Exception as e:
        logging.critical('Unable to discern hostname - ' + str(e) + '.')
        try:
            _send_email(
                subject = '? - Unable to discern hostname',
                body = 'The xfer-web script reports that it encountered an error while trying to discern the hostname of the machine it is executing from. Good luck finding it!',
                level = 'error'
            )
        except Exception as mail_e:
            logging.warning('Unable to send email - ' + str(mail_e) + '.')
        exit(1)
    logging.debug('Hostname: ' + hostname)

    # Verify and parse the configuration file
    logging.debug('Verifying existence of configuration file...')
    if not os.path.isfile(args.config_path):
        logging.critical('Specified configuration file does not exist.')
        send_email(
            'Specified configuration file does not exist',
            CONFIG_FILE_DOESNT_EXIST,
            'error'
        )
        exit(1)
    logging.debug('Parsing configuration file...')
    try:
        config = ConfigParser.SafeConfigParser()
        with open(args.config_path, 'r') as cf:
            config.readfp(cf)
    except Exception as e:
        logging.critical('Unable to parse specified configuration file - ' + str(e) + '.')
        send_email(
            'Unable to parse specified configuration file',
            CONFIG_CANT_PARSE,
            'error'
        )
        exit(1)

    # Verify the existence of the environment and specified configuration target
    if not config.has_section('global'):
        logging.critical('Invalid configuration file - missing "global" section.')
        send_email(
            'invalid configuration file',
            CONFIG_MISSING_GLOBAL,
            'error'
        )
        exit(1)
    if not config.has_option('global', 'environment'):
        logging.critical('Invalid configuration file - missing "environment" specification in "global" section.')
        send_email(
            'invalid configuration file',
            CONFIG_MISSING_ENV,
            'error'
        )
        exit(1)
    try:
        raw_env_spec = config.get('global', 'environment')
        logging.debug('RAW ENVIRONMENT SPEC: ' + raw_env_spec)
        env_spec = ast.literal_eval(raw_env_spec)
    except Exception as e:
        logging.critical('Unable to parse environment specification - ' + str(e))
        send_email(
            'Unable to parse environment specification',
            CONFIG_CANT_PARSE_ENV,
            'error'
        )
        exit(1)
    if not isinstance(env_spec, dict):
        logging.critical(
            'Unable to parse environment specification - specification does not parse to a dictionary.'
        )
        send_email(
            'Unable to parse environment specification',
            CONFIG_CANT_PARSE_ENV,
            'error'
        )
        exit(1)
    if not hostname in env_spec:
        logging.critical(
            'No environment mapping specified for executing host.'
        )
        send_email(
            'No environment mapping specified for executing host',
            HOSTNAME_NOT_IN_ENV,
            'error'
        )
        exit(1)
    conf_environment = env_spec[hostname]
    logging.debug('ENVIRONMENT: {env}'.format(env=conf_environment))
    conf_sec = '{env}/{target}'.format(env=conf_environment, target=args.target)
    logging.debug('SECTION: {sec}'.format(sec=conf_sec))
    if not config.has_section(conf_sec):
        logging.critical('Invalid target specification - specified target does not exist within configured environment.')
        send_email(
            'Invalid target specification',
            CONFIG_BAD_TARGET,
            'error'
        )
        exit(1)

    # Visually indicate a dry-run
    if args.dry_run:
        logging.info('----- {tgt} (DRY RUN) -----'.format(tgt=conf_sec))
    else:
        logging.info('----- {tgt} -----'.format(tgt=conf_sec))

    # Keep track if we did anything
    found_method = False

    # Convert global section variables into a dictionary for interpolation
    try:
        global global_settings
        global_settings = dict([(key, val.strip('"')) for key, val in config.items('global')])
        global_settings.pop('environment', None)
    except Exception as e:
        logging.critical('Unable to parse global settings - ' + str(e) + '.')
        send_email(
            'Unable to parse global settings',
            CONFIG_CANT_PARSE,
            'error'
        )
        exit(1)
    logging.debug('GLOBAL SETTINGS: ' + str(global_settings))

    # Handle local file copies
    if config.has_option(conf_sec, 'local_copy'):
        found_method = True
        try:
            raw_lc_spec = config.get(conf_sec, 'local_copy')
            logging.debug('RAW LOCAL COPY SPEC: ' + raw_lc_spec)
            lc_spec = ast.literal_eval(raw_lc_spec)
        except Exception as e:
            logging.critical('Unable to parse local copy specification - ' + str(e) + '.')
            send_email(
                'Unable to parse local copy specification',
                CONFIG_CANT_PARSE_LC,
                'error'
            )
            exit(1)
        if not isinstance(lc_spec, dict):
            logging.critical(
                'Unable to parse local copy specification - specification does not parse to a dictionary.'
            )
            send_email(
                'Unable to parse local copy specification',
                CONFIG_CANT_PARSE_LC,
                'error'
            )
            exit(1)
        handle_local_copy(lc_spec)

    # Handle rsyncs
    if config.has_option(conf_sec, 'rsync'):
        found_method = True
        if not os.path.isfile(args.rsync_executable):
            logging.critical('Specified rsync executable does not exist.')
            send_email(
                'Specified rsync executable does not exist',
                RSYNC_EXEC_MISSING,
                'error'
            )
            exit(1)
        try:
            raw_rsync_spec = config.get(conf_sec, 'rsync')
            logging.debug('RAW RSYNC SPEC: ' + raw_rsync_spec)
            rsync_spec = ast.literal_eval(raw_rsync_spec)
        except Exception as e:
            logging.critical('Unable to parse rsync specification - ' + str(e) + '.')
            send_email(
                'Unable to parse rsync specification',
                CONFIG_CANT_PARSE_RSYNC,
                'error'
            )
            exit(1)
        if not isinstance(rsync_spec, dict):
            logging.critical(
                'Unable to parse rsync specification - specification does not parse to a dictionary of host-specific configurations.'
            )
            send_email(
                'Unable to parse rsync specification',
                CONFIG_CANT_PARSE_RSYNC,
                'error'
            )
            exit(1)
        handle_rsync(rsync_spec)

    # Handle database migrations
    if config.has_option(conf_sec, 'flyway'):
        found_method = True
        if not os.path.isfile(args.flyway_executable):
            logging.critical('Specified flyway executable does not exist.')
            send_email(
                'Specified flyway executable does not exist',
                FLYWAY_EXEC_MISSING,
                'error'
            )
            exit(1)
        if not os.path.isfile(args.flyway_config):
            logging.critical('Specified flyway configuration file does not exist.')
            send_email(
                'Specified flyway configuruation file does not exist',
                FLYWAY_CONFIG_MISSING,
                'error'
            )
            exit(1)
        try:
            raw_flyway_spec = config.get(conf_sec, 'flyway')
            logging.debug('RAW FLYWAY SPEC: ' + raw_flyway_spec)
            flyway_spec = ast.literal_eval(raw_flyway_spec)
        except Exception as e:
            logging.critical('Unable to parse flyway specification - ' + str(e) + '.')
            send_email(
                'Unable to parse flyway specification',
                CONFIG_CANT_PARSE_FLYWAY,
                'error'
            )
            exit(1)
        if not isinstance(flyway_spec, list):
            logging.critical(
                'Unable to parse flyway specification - specification does not parse to a list of configuration dictionaries.'
            )
            send_email(
                'Unable to parse flyway specification',
                CONFIG_CANT_PARSE_FLYWAY,
                'error'
            )
            exit(1)
        handle_flyway(flyway_spec)

    # Handle local arbitrary command execution
    if config.has_option(conf_sec, 'command'):
        found_method = True
        try:
            raw_cmd_spec = config.get(conf_sec, 'command')
            logging.debug('RAW CMD SPEC: ' + raw_cmd_spec)
            cmd_spec = ast.literal_eval(raw_cmd_spec)
        except Exception as e:
            logging.critical('Unable to parse arbitrary command specification - ' + str(e) + '.')
            send_email(
                'Unable to parse arbitrary command specification',
                CONFIG_CANT_PARSE_CMD,
                'error'
            )
            exit(1)
        if not isinstance(cmd_spec, list):
            logging.critical(
                'Unable to parse arbitrary command specification - specification does not parse to a list of shell commands.'
            )
            send_email(
                'Unable to parse arbitrary command specification',
                CONFIG_CANT_PARSE_CMD,
                'error'
            )
            exit(1)
        handle_cmd(cmd_spec)

    # We are done!
    if not found_method:
        logging.warning('No deployment method defined in specified configuration target.')
        send_email(
            'No deployment method defined in specified configuration target',
            CONFIG_NO_METHOD,
            'warning'
        )
        exit(0)
    else:
        logging.info('Transfer process complete.')
        send_email(
            'Transfer process complete',
            DONE,
            'info'
        )
        exit(0)


def parse_arguments():
    '''
    Parses the command-line arguments into a global registry called "args".
    '''
    argparser = argparse.ArgumentParser(
        description = HELP_DESCRIPTION,
        epilog = HELP_EPILOG,
        usage = 'xfer-staging.py TARGET [...]',
        add_help = False,
        formatter_class = lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=45, width=100)
        )
    argparser.add_argument(
        '-c',
        '--config',
        default = '/deploy/bin/xfer-staging.conf',
        dest = 'config_path',
        help = 'Specifies a configuration file to load. Defaults to "/deploy/bin/xfer-staging.conf".',
        metavar = 'FILE'
        )
    argparser.add_argument(
        '--dry-run',
        action = 'store_true',
        dest = 'dry_run',
        help = 'Specifies that the transfer script should only execute as a dry-run, preventing any changes from actually occuring.'
        )
    argparser.add_argument(
        '-e',
        '--email-level',
        choices = ['never', 'error', 'warning', 'completion'],
        default = 'error',
        dest = 'email_level',
        help = 'Specifies the condition at which the script should send an email, being "never", "error", "warning", or "completion". Defaults to "error".',
        metavar = 'L'
        )
    argparser.add_argument(
        '--email-to',
        default = 'foo@example.com',
        dest = 'email_to',
        help = 'Specifies the email address to recieve sent emails. Defaults to "foo@example.com".',
        metavar = 'EMAIL'
        )
    argparser.add_argument(
        '--flyway-callbacks',
        default = '',
        dest = 'flyway_callbacks',
        help = 'Specifies one or more flyway mysql migration callback classes, as if passed-in via "-callbacks=". Defaults to "" (nothing).',
        metavar = 'C'
        )
    argparser.add_argument(
        '--flyway-config',
        default = '/opt/flyway-3.1/conf/migrations.properties',
        dest = 'flyway_config',
        help = 'Specifies the configuration file passed to the flyway utility when handling mysql migrations. Defaults to "/opt/flyway-3.1/conf/migrations.properties"',
        metavar = 'FILE'
        )
    argparser.add_argument(
        '--flyway-executable',
        default = '/opt/flyway-3.1/flyway',
        dest = 'flyway_executable',
        help = 'Specifies a file path to the flyway executable utilized in database migration specifications. Defaults to "/opt/flyway-3.1/flyway".',
        metavar = 'FILE'
        )
    argparser.add_argument(
        '-h',
        '--help',
        action = 'help',
        help = 'Displays help and usage information.'
        )
    argparser.add_argument(
        '--log-file',
        default = '/var/log/xfer-staging.log',
        dest = 'log_file',
        help = 'Specifies the log file to write to. Defaults to "/var/log/xfer-webapp.log".',
        metavar = 'FILE'
        )
    argparser.add_argument(
        '-l',
        '--log-level',
        choices = ['info', 'debug'],
        default = 'info',
        dest = 'log_level',
        help = 'Specifies the log level of the script, being either "info" or "debug". Defaults to "info".',
        metavar = 'L'
        )
    argparser.add_argument(
        '--log-mode',
        choices = ['append', 'overwrite'],
        default = 'append',
        dest = 'log_mode',
        help = 'Specifies whether to "append" or "overwrite" the specified log file. Defaults to "append".',
        metavar = 'M'
        )
    argparser.add_argument(
        '--rsync-executable',
        default = '/usr/bin/rsync',
        dest = 'rsync_executable',
        help = 'Specifies a file path to the rsync executable utilized rsync specifications. Defaults to "/usr/bin/rsync".',
        metavar = 'FILE'
        )
    argparser.add_argument(
        'target',
        help = 'Specifies the configuration target to execute.'
        )
    global args
    args = argparser.parse_args()


def send_email(subject, body, level='error'):
    '''
    Sends an email to the configured recipients with the specified body, subject,
    and alert level. Whether the email actually gets sent is dependent on the
    alert level specified by "args.email_level".
    '''
    try:
        _send_email(hostname + ' - ' + subject, body, level)
    except Exception as mail_e:
        logging.warning('Unable to send email - ' + str(mail_e) + '.')

# ------------------------------------



# --------- Boilerplate Magic --------

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError) as ki:
        sys.stderr.write('Recieved keyboard interrupt!\n')
        exit(100)

# ------------------------------------
