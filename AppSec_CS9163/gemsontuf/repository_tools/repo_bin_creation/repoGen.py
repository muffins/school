#!/usr/bin/env python

"""
<Program Name>
  quickstart.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 2012.  Based on a previous version by Geremy Condra.

<Modified>
  December 2013.  Red Team (AppSec class)

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This script acts as a handy quickstart for TUF, helping project and
  repository maintainers get into the game as quickly and painlessly as
  possible.  'quickstart.py' creates the metadata files for all the top-level
  roles (along with their respective cryptographic keys), all of the
  target files specified by the user, and a configuration file named
  'config.cfg'.  The user may then use the 'signercli' script to modify,
  if they wish, the basic repository created by 'quickstart.py'.

  If executed successfully, 'quickstart.py' saves the 'repository', 'keystore',
  and 'client' directories to the current directory.  The 'repository' directory
  should be transferred to the server responding to TUF repository requests.
  'keystore' and the individual encrypted key files should be securely stored
  and managed by the repository maintainer; these files will be needed again
  when modifying the metadata files.  'client' should be initially distributed
  to users by the software updater utilizing TUF.

  The Update Framework may be tested locally with the output of 'quickstart.py'
  in two easy steps.

  # If you need a basic server for testing purposes
  $ cd repository; python -m SimpleHTTPServer 8001

  # This next step is performed by the client.  Here we are using the basic
  # client, which will securely update all target files.  In a new terminal ...
  $ cd client; python basic_client.py --repo http://localhost:8001

  # You can also test a custom client by running the 'example_client.py' script
  # provided with TUF.
  $ cd client; python example_client.py


  'quickstart.py' is invoked once to set up the repository.  'signercli.py' is
  used to update the repository on the server.  In the case of updated targets,
  the repository maintainer would simply add/delete target files from the
  'targets' directory on the server and execute the following three commands to
  generate updated metadata files:

  $ python signercli.py --maketargets ./keystore
  $ python signercli.py --makerelease ./keystore
  $ python signercli.py --maketimestamp ./keystore

  The next time the client queries the server, the top-level metadata files are
  updated and any updated target files downloaded.


<Usage>
  $ python quickstart.py --<option> argument

  Examples:
  $ python quickstart.py --project ./project-files/
  $ python quickstart.py --project ./project-files/ --verbose 1


  'quickstart.py' will request threshold values for the top-level roles.
  For recommended values and more information on the files generated by
  this script, consult the documentation provided in the 'docs' directory.

<Options>
  --verbose:
    Set the verbosity level of logging messages.  Accepts values 1-5.
    The lower the setting, the greater the verbosity.

  --project:
    Specify the project directory containing the target files to be
    served by the TUF repository.

"""

import time
import datetime
import getpass
import sys
import os
import optparse
import ConfigParser
import shutil
import tempfile
import logging
import errno

import tuf
import tuf.repo.signerlib
import tuf.repo.keystore
import tuf.formats
import tuf.util
import tuf.log

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.quickstart')

# Set the default file names for the top-level roles.
# For instance: in 'signerlib.py', ROOT_FILENAME = 'root.txt'.
ROOT_FILENAME = tuf.repo.signerlib.ROOT_FILENAME
TARGETS_FILENAME = tuf.repo.signerlib.TARGETS_FILENAME
RELEASE_FILENAME = tuf.repo.signerlib.RELEASE_FILENAME
TIMESTAMP_FILENAME = tuf.repo.signerlib.TIMESTAMP_FILENAME

# Expiration date, in seconds, of the top-level roles (excluding 'Root').
# The expiration time of the 'Root' role is set by the user.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.
# Initial 'targets.txt' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 

# Initial 'release.txt' expiration time of 1 week. 
RELEASE_EXPIRATION = 604800 

# Initial 'timestamp.txt' expiration time of 1 day.
TIMESTAMP_EXPIRATION = 86400

# The maximum number of attempts the user has to enter
# valid input.
MAX_INPUT_ATTEMPTS = 3

# Role Passwords dictionary
# For Dev only, don't use in production
ROLE_PASSWORDS = {
  'root':      ['mysecret1', 'mysecret2', 'mysecret3'],
  'targets':   ['mysecret4', 'mysecret5'],
  'release':   ['mysecret6', 'mysecret7'],
  'timestamp': ['mysecret8']
}

ROLE_THRESHOLDS = {
  'root':      3,
  'targets':   2,
  'release':   2,
  'timestamp': 1
}


def _prompt(message, result_type=str):
  """
    Prompt the user for input by printing 'message', converting
    the input to 'result_type', and returning the value to the
    caller.

  """

  return result_type(raw_input(message))


def _get_password(prompt='Password: ', confirm=False):
  """
    Return the password entered by the user.  If 'confirm'
    is True, the user is asked to enter the previously
    entered password once again.  If they match, the
    password is returned to the caller.

  """

  while True:
    # getpass() prompts the user for a password without echoing
    # the user input.
    password = getpass.getpass(prompt, sys.stderr)
    if not confirm:
      return password
    password2 = getpass.getpass('Confirm: ', sys.stderr)
    if password == password2:
      return password
    else:
      print 'Mismatch; try again.'


def build_repository(project_directory):
  """
  <Purpose>
    Build a basic TUF repository.  All of the required files needed by a
    repository mirror are created, such as the metadata files of the top-level
    roles, cryptographic keys, and the directories containing all of the target
    files.

  <Arguments>
    project_directory:
      The directory containing the target files to be copied over to the
      targets directory of the repository.

  <Exceptions>
    tuf.RepositoryError, if there was an error building the repository.

  <Side Effects>
    The repository files created are written to disk to the current
    working directory.

  <Returns>
    None.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.RepositoryError' if there is a mismatch.
  try:
    tuf.formats.PATH_SCHEMA.check_match(project_directory)
  except tuf.FormatError, e:
    message = str(e)
    raise tuf.RepositoryError(message)
  
  # Verify the 'project_directory' argument.
  project_directory = os.path.abspath(project_directory)
  try:
    tuf.repo.signerlib.check_directory(project_directory)
  except (tuf.FormatError, tuf.Error), e:
    message = str(e)
    raise tuf.RepositoryError(message)
  
  # Handle the expiration time.  The expiration date determines when
  # the top-level roles expire.
  prompt_message = \
    '\nWhen would you like your "root.txt" metadata to expire? (mm/dd/yyyy): '
  timeout = 360 #None
  # for attempt in range(MAX_INPUT_ATTEMPTS):
  #   # Get the difference between the user's entered expiration date and today's
  #   # date.  Convert and store the difference to total days till expiration.
  #   try:
  #     input_date = _prompt(prompt_message)
  #     expiration_date = datetime.datetime.strptime(input_date, '%m/%d/%Y')
  #     time_difference = expiration_date - datetime.datetime.now()
  #     timeout = time_difference.days
  #     if timeout < 1:
  #       raise ValueError
  #     break
  #   except ValueError, e:
  #     message = 'Invalid expiration date entered'
  #     logger.error(message)
  #     timeout = None
  #     continue

  # Was a valid value for 'timeout' set?
  if timeout is None:
    raise tuf.RepositoryError('Could not get a valid expiration date\n')

  # Build the repository directories.
  metadata_directory = None
  targets_directory = None

  # Save the repository directory to the current directory, with
  # an initial name of 'repository'.  The repository maintainer
  # may opt to rename this directory and should transfer it elsewhere,
  # such as the webserver that will respond to TUF requests.
  repository_directory = os.path.join(os.getcwd(), 'repository')
  
  # Copy the files from the project directory to the repository's targets
  # directory.  The targets directory will hold all the individual
  # target files.
  targets_directory = os.path.join(repository_directory, 'targets')
  # temporary_directory = tempfile.mkdtemp()
  # temporary_targets = os.path.join(temporary_directory, 'targets')
  # shutil.copytree(project_directory, temporary_targets)
  
  # Remove the log file created by the tuf logger, if it exists.
  # It might exist if the current directory was specified as the
  # project directory on the command-line.
  # log_filename = tuf.log._DEFAULT_LOG_FILENAME
  # if log_filename in os.listdir(temporary_targets):
  #   log_file = os.path.join(temporary_targets, log_filename)
  #   os.remove(log_file)

  # Try to create the repository directory.
  # try:
  #   os.mkdir(repository_directory)
  # # 'OSError' raised if the directory cannot be created.
  # except OSError, e:
  #   message = 'Trying to create a new repository over an old repository '+\
  #     'installation.  Remove '+repr(repository_directory)+' before '+\
  #     'trying again.'
  #   if e.errno == errno.EEXIST:
  #     raise tuf.RepositoryError(message)
  #   else:
  #     raise

  # Move the temporary targets directory into place now that repository
  # directory has been created and remove previously created temporary
  # directory.
  # shutil.move(temporary_targets, targets_directory)
  # os.rmdir(temporary_directory)
  
  # Try to create the metadata directory that will hold all of the
  # metadata files, such as 'root.txt' and 'release.txt'.
  try:
    metadata_directory = os.path.join(repository_directory, 'metadata')
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.mkdir(metadata_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise

  # Set the keystore directory.
  keystore_directory = os.path.join(os.getcwd(), 'keystore')

  # Try to create the keystore directory.
  try:
    os.mkdir(keystore_directory)
  # 'OSError' raised if the directory cannot be created.
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise

  # Build the keystore and save the generated keys.
  role_info = {}
  for role in ['root', 'targets', 'release', 'timestamp']:
    # Ensure the user inputs a valid threshold value.
    role_threshold = ROLE_THRESHOLDS[role] #None
    # for attempt in range(MAX_INPUT_ATTEMPTS):
    #   prompt_message = \
    #     '\nEnter the desired threshold for the role '+repr(role)+': '

    #   # Check for non-integers and values less than one.
    #   try:
    #     role_threshold = _prompt(prompt_message, int)
    #     if not tuf.formats.THRESHOLD_SCHEMA.matches(role_threshold):
    #       raise ValueError
    #     break
    #   except ValueError, e:
    #     message = 'Invalid role threshold entered'
    #     logger.warning(message)
    #     role_threshold = None
    #     continue

    # Did the user input a valid threshold value?
    if role_threshold is None:
      raise tuf.RepositoryError('Could not build the keystore\n')

    # Retrieve the password(s) for 'role', generate the key(s),
    # and save them to the keystore.
    for threshold in range(role_threshold):
      # message = 'Enter a password for '+repr(role)+' ('+str(threshold+1)+'): '
      password = ROLE_PASSWORDS[role][threshold] #_get_password(message, confirm=True)
      key = tuf.repo.signerlib.generate_and_save_rsa_key(keystore_directory,
                                                         password)
      try:
        role_info[role]['keyids'].append(key['keyid'])
      except KeyError:
        info = {'keyids': [key['keyid']], 'threshold': role_threshold}
        role_info[role] = info

  # At this point the keystore is built and the 'role_info' dictionary
  # looks something like this:
  # {'keyids : [keyid1, keyid2] , 'threshold' : 2}

  # Build the configuration file.
  config_filepath = tuf.repo.signerlib.build_config_file(repository_directory,
                                                         timeout, role_info)

  # Generate the 'root.txt' metadata file. 
  # Newly created metadata start at version 1.  The expiration date for the
  # 'Root' role is extracted from the configuration file that was set, above,
  # by the user.
  root_keyids = role_info['root']['keyids']
  tuf.repo.signerlib.build_root_file(config_filepath, root_keyids,
                                     metadata_directory, 1)

  # Generate the 'targets.txt' metadata file.
  targets_keyids = role_info['targets']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+TARGETS_EXPIRATION)
  tuf.repo.signerlib.build_targets_file([targets_directory], targets_keyids,
                                        metadata_directory, 1,
                                        expiration_date)

  # Generate the 'release.txt' metadata file.
  release_keyids = role_info['release']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+RELEASE_EXPIRATION)
  tuf.repo.signerlib.build_release_file(release_keyids, metadata_directory,
                                        1, expiration_date)

  # Generate the 'timestamp.txt' metadata file.
  timestamp_keyids = role_info['timestamp']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+TIMESTAMP_EXPIRATION)
  tuf.repo.signerlib.build_timestamp_file(timestamp_keyids, metadata_directory,
                                          1, expiration_date)

  # Generate the 'client' directory containing the metadata of the created
  # repository.  'tuf.client.updater.py' expects the 'current' and 'previous'
  # directories to exist under 'metadata'.
  client_metadata_directory = os.path.join(os.getcwd(), 'client', 'metadata')
  try:
    os.makedirs(client_metadata_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      message = 'Cannot create a fresh client metadata directory: '+\
        repr(client_metadata_directory)+'.  The client metadata '+\
        'will need to be manually created.  See the README file.'
      logger.warn(message)
    else:
      raise

  # Move the metadata to the client's 'current' and 'previous' directories.
  client_current = os.path.join(client_metadata_directory, 'current')
  client_previous = os.path.join(client_metadata_directory, 'previous')
  shutil.copytree(metadata_directory, client_current)
  shutil.copytree(metadata_directory, client_previous)


def parse_options():
  """
  <Purpose>
    Parse the command-line options and set the logging level,
    as specified by the user using the '--verbose' option.
    The user must also set the '--project' option.  If unset,
    the current directory is used as the location of the project
    files.  The project files are copied by 'quickstart.py' and
    saved to the repository's targets directory.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    The 'options.PROJECT_DIRECTORY' string.

  """

  parser = optparse.OptionParser()

  # Add the options supported by 'quickstart' to the option parser.
  parser.add_option('--verbose', dest='VERBOSE', type=int, default=3,
                    help='Set the verbosity level of logging messages.'
                         'The lower the setting, the greater the verbosity.')

  parser.add_option('--project', dest='PROJECT_DIRECTORY', type='string',
                    default='.', help='Specify the directory containing the '
                    'project files to host on the TUF repository.')

  options, args = parser.parse_args()

  # Set the logging level.
  if options.VERBOSE == 5:
    tuf.log.set_log_level(logging.CRITICAL)
  elif options.VERBOSE == 4:
    tuf.log.set_log_level(logging.ERROR)
  elif options.VERBOSE == 3:
    tuf.log.set_log_level(logging.WARNING)
  elif options.VERBOSE == 2:
    tuf.log.set_log_level(logging.INFO)
  elif options.VERBOSE == 1:
    tuf.log.set_log_level(logging.DEBUG)
  else:
    tuf.log.set_log_level(logging.NOTSET)

  # Return the directory containing the project files.  These files
  # are copied over to the targets directory of the repository.
  return options.PROJECT_DIRECTORY 


if __name__ == '__main__':

  # Parse the options and set the logging level.
  project_directory = parse_options()

  # Build the repository.  The top-level metadata files, cryptographic keys,
  # target files, and the configuration file are created.
  try:
    build_repository(project_directory)
  except tuf.RepositoryError, e:
    sys.stderr.write(str(e)+'\n')
    sys.exit(1)

  print 'Successfully created the repository.'
  sys.exit(0)