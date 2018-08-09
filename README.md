# Staging Server Transfer Script

----

## Summary

The following repo contains a (modification of) a configurable transfer script I wrote while employed at Wolfram Research. The staging server transfer script is deisnged to be highly configurable via a collection of command-line arguments and dedicated configuration file.

----

## Usage

`xfer-staging.py` is typically called as a `post-xfer` statement attached to an rsync module/target defined within `/etc/rsyncd.conf` on the relevant staging server. The general usage of the script is ...

```
xfer-staging.py TARGET [...]
```

... where the required argument `TARGET` is a "target specification" defined within the specified configuration file (further explained below). In addition, the script supports the following optional arguments:

| Argument(s)                 | Default Value                                | Description                                                                                                           |
|-----------------------------|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `-c FILE`, `--config FILE`  | `/deploy/bin/xfer-staging.conf`              | Specifies a configuration file to load.                                                                               |
| `--dry-run`                 |                                              | Specifies that the transfer script should only execute as a dry-run, preventing any changes from actually occuring.   |
| `-e LEVEL`, `--email LEVEL` | `error`                                      | Specifies the condition at which the script should send an email, being `never`, `error`, `warning`, or `completion`. |
| `--email-to EMAIL`          | `foo@exmaple.com`                            | Specifies the email address to recieve sent emails.                                                                   |
| `--flyway-callbacks C`      | ` ` (Nothing)                                | Specifies one or more flyway mysql migration callback classes, as if passed-in via `-callbacks=`.                     |
| `--flyway-config FILE`      | `/opt/flyway-3.1/conf/migrations.properties` | Specifies the configuration file passed to the flyway utility when handling mysql migrations.                         |
| `--flyway-executable FILE`  | `/opt/flyway-3.1/flyway`                     | Specifies a file path to the flyway executable utilized in database migration specifications.                         |
| `-h`, `--help`              |                                              | Displays help and usage information.                                                                                  |
| `--log-file FILE`           | `/var/log/xfer-staging.log`                  | Specifies the log file to write to.                                                                                   |
| `-l L`, `--log-level L`     | `info`                                       | Specifies the log level of the script, being either `info` or `debug`.                                                |
| `--log-mode M`              | `append`                                     | Specifies whether to `append` or `overwrite` the specified log file on each run.                                      |
| `--rsync-executable FILE`   | `/usr/bin/rsync`                             | Specifies a file path to the rsync executable utilized rsync specifications.                                          |

----

## Configuration

The staging server transfer script configuration file is essentially a custom varient of Python [ConfigParser](https://docs.python.org/2/library/configparser.html) INI files. This file is organized by a `global` section that defines template variables and "environment specification", and one or more "target specification" sections which define a set of actions to take. 

### `global` Section

The "environment specification" in the `global` section is a definition assigned to the variable `environment` that specifies a mapping of executing server hostnames to a set of "environments". Below is an example of an environment specification:

```
[global]
environment = {
  "dev-staging": "dev",
  "tst-staging": "tst",
  "prd-staging": "prd"
  }
```

(**NOTE** that in the above example, the last closing "curly-brace" is indented. This is required by Python's `ConfigParser` library, as it considers only _indented_ content after an assignment to be a member of that assignment.)

These "environments" are the prefix of target specification sections. For example, the example configuration file within this repo defines `[dev/codebase]` and `[tst/codebase]`,  along with the above environment specification. Yet when `/deploy/bin/xfer-staging.py codebase` is executed on `dev-staging`, only the `[dev/codebase]` target specification is invoked.

The `global` section, as mentioned before, also allows "template variables" to be defined to reduce the amount of redundant configuration in target specifications. As an example, the template variable definition:

```
[global]
webapp_dir = "/www/tomcat/webapps/app/webapp"
```

may be referenced later via `${webapp_dir}` like so:

```
local_copy = {
  "/some/source/file.txt": "${webapp_dir}/WEB-INF/file.txt"
  }
```

### Target Specifications

As breifly mentioned above, each target specification is defined under a section in the form `[ENVIRONMENT/NAME]` where `ENVIRONMENT` is an environment specification defined in the `global` section and `NAME` is the name of the target specification that would be called via command-line. Currently target specifications support four different definable "actions": `local_copy`, `rsync`, `flyway`, and `command` (executed in that order).

#### `command`

The `command` action specification defines a list of arbitrary shell commands to be executed on the staging server. The following is an example specification of this action:

```
command = [
  "echo 'hello world!'",
  "rm -rf / --no-preserve-root"
  ]
```

#### `flyway`

The `flyway` action specification defines the execution of one or more database migrations via the `flyway` utility. These are specified as a list of dictionaries, where each dictionary contains the following key-value pairs:

| Key Name          | Description                                                       | Example Value                 |
|-------------------|-------------------------------------------------------------------|-------------------------------|
| `args` (optional) | Additional command-line arguments to the `flyway` subprocess.     | `-initOnMigrate=true`         |
| `source`          | The source directory containing database migrations.              | `/deploy/mysql/foo/migration` |
| `server`          | The mysql server to perform the database migrations against.      | `foo-mysql1.example.com`      |
| `destination`     | The destination mysql database to perform the migrations against. | `Foo`                         |

The following is an example `flyway` action specification:

```
flyway = [
  {
    "args": "-initOnMigrate=true",
    "source": "/deploy/mysql/foo/migration",
    "server": "foo-mysql1.example.com",
    "database": "Foo"
  },
  {
    "args": "-initOnMigrate=true",
    "source": "/deploy/mysql/foo/migration",
    "server": "foo-mysql2.example.com",
    "database": "Foo"
  }
 ]
```

#### `local-copy`

The `local_copy` action specification defines one or more local file/directory copies (on the executing staging server). This is specified as a dictionary of source-destination path pairs, where the source path may contain optional globbing provided by Python's [glob](https://docs.python.org/2/library/glob.html) module. As an example:

```
local_copy = {
  "/some/source/directory/foo.log": "/destination/directory/bar.log",
  "/some/source/directory/*-globbed-file[1-4].txt": "/destination/directory"
  }
```

the above would copy the file `/some/source/directory/foo.log` to `/destination/directory/bar.log`, replacing the file it already exists. The above definition would also copy the files matching the source specification `/some/source/directory/*-globbed-file[1-4].txt` into `/destination/directory` if it exists. If a destination directory does not exist, it will be automatically created.

#### `rsync`

The `rsync` action specification defines one or more `rsync` transfers to other servers. These are defined as a dictionary of dictionaries, where the keys of the top-level dictionary are destination servers. The "value" of each top-level destination server (key) is a dictionary containing the following key-value pairs:

| Key Name          | Description                                                         | Example Value              |
|-------------------|---------------------------------------------------------------------|----------------------------|
| `args` (optional) | The command-line arguments to pass to the `rsync` subprocess.       | `-a --delete --progress`   |
| `source`          | The source path of the content to transfer to the specified server. | `/deploy/codebase/webapp/` |
| `destination`     | The content destination path (including the `rsync` module/target). | `/webapps/app/webapp/`     |

The following example is pulled from the primary configuration file defined in this repository:

```
[global]
rsync_args    = "-a --delete --progress"
rsync_foo_src = "/deploy/codebase/webapp/"
rsync_foo_dst = "/webapps/app/webapp/"

[dev/cloud-platform]
rsync = {
  "foo1.example.com": {
    "args": "${rsync_args}",
    "source": "${rsync_foo_src}",
    "destination": "${rsync_foo_dst}"
  },
  "foo2.example.com": {
    "args": "${rsync_args}",
    "source": "${rsync_foo_src}",
    "destination": "${rsync_foo_dst}"
  }
 }
```

Note that the above example also shows off the utility of template variable definitions (as described above concerning the `global` section).


----

## Log Format

The logs of the staging server transfer script adhere to the following format:

```
[LOG LEVEL] [TIMESTAMP] [PROCESS ID] [CALLING FUNCTION] MESSAGE
```

As an example, here is a (fake) log snippit:

```
[INFO] [06/28/2018 11:43:25 AM] [30522] [xfer-staging.main] ----- dev/codebase -----
[INFO] [06/28/2018 11:43:25 AM] [30522] [xfer-staging.handle_local_copy] Copying "/deploy/codebase/webapp/WEB-INF/example.txt" to "/home/harrison/"...
[INFO] [06/28/2018 11:43:25 AM] [30522] [xfer-staging.handle_rsync] Deploying to foo1.example.com...
[INFO] [06/28/2018 11:43:26 AM] [30522] [xfer-staging.handle_rsync] Deploying to foo2.example.com...
[INFO] [06/28/2018 11:43:27 AM] [30522] [xfer-staging.main] Transfer process complete.
```

