#!/usr/bin/env bash

# Note: make sure this has LF endings before packaging the installer!

# User-configurable parameters
GREATDANEENGINE_JSVC=$(which jsvc)
GREATDANEENGINE_USER=$USER
GREATDANEENGINE_LOGDIR=/tmp
GREATDANEENGINE_PIDFILE=/tmp/greatdaneengine.pid
GREATDANEENGINE_START_WAIT_SECONDS=10

# Non-configurable variables
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREATDANEENGINE_HOME=$(dirname "$DIR")
GREATDANEENGINE_LOG_OUT="$GREATDANEENGINE_LOGDIR/greatdaneengine.stdout"
GREATDANEENGINE_LOG_ERR="$GREATDANEENGINE_LOGDIR/greatdaneengine.stderr"

#GREATDANEENGINE_CLASSPATH="$GREATDANEENGINE_HOME/lib/*:"
GREATDANEENGINE_CLASSPATH=$(find "$GREATDANEENGINE_HOME/lib" -name "*.jar" | awk -v ORS=: '{ print $1 }' | sed 's/:$//')
GREATDANEENGINE_CLASS="com.grierforensics.greatdane.Daemon"

if [[ -z "$JAVA_HOME" ]]; then
    case "$(uname -s)" in
        Darwin)
            export JAVA_HOME=$(/usr/libexec/java_home)
            ;;
        Linux)
            echo "Please set JAVA_HOME, which may be one of:"
            echo " - /usr/java/latest"
            echo " - /usr/lib/jvm/java"
            echo " - /usr/lib/jvm/java-1.8.0-openjdk[...]"
            exit 1
            ;;
        *)
            echo "Please set JAVA_HOME"
            exit 1
            ;;
    esac
fi

if [[ -z "$GREATDANEENGINE_JSVC" ]]; then
    echo "Please install Apache Commons-Daemon jsvc:"
    echo " - RHEL/CentOS:     sudo yum install apache-commons-daemon-jsvc"
    echo " - Debian/Ubuntu:   sudo apt-get install jsvc"
    echo " - OS X (Homebrew): brew install jsvc"
    exit 1
fi

greatdaneengine_daemon()
{
    $GREATDANEENGINE_JSVC \
        -cwd "$GREATDANEENGINE_HOME" \
        -home "$JAVA_HOME" \
        -cp $GREATDANEENGINE_CLASSPATH \
        -user $GREATDANEENGINE_USER \
        -wait $GREATDANEENGINE_START_WAIT_SECONDS \
        -outfile $GREATDANEENGINE_LOG_OUT \
        -errfile $GREATDANEENGINE_LOG_ERR \
        -pidfile $GREATDANEENGINE_PIDFILE \
        $1 \
        $GREATDANEENGINE_CLASS
}

case "$1" in
    start)
        greatdaneengine_daemon
            ;;
    stop)
        greatdaneengine_daemon "-stop"
            ;;
    restart)
        if [ -f "$GREATDANEENGINE_PIDFILE" ]; then
            greatdaneengine_daemon "-stop"
            greatdaneengine_daemon
        else
            echo "Service is not running."
            exit 1
        fi
            ;;
    status)
        if [ -f "$GREATDANEENGINE_PIDFILE" ]; then
            echo "Service is running."
        else
            echo "Service is not running."
            exit 2
        fi
            ;;
    *)
        echo "usage: $(basename $0) {start|stop|restart|status}" >&2
        exit 3
            ;;
esac
