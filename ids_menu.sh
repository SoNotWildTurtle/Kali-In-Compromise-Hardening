#!/bin/bash
# ids_menu.sh - Configure IDS notification and network discovery response

CONF_FILE="/etc/nn_ids.conf"
[ -w "$CONF_FILE" ] || CONF_FILE="$(dirname "$0")/nn_ids.conf"

get_value() {
    grep -E "^$1=" "$CONF_FILE" | cut -d'=' -f2
}

set_value() {
    if grep -qE "^$1=" "$CONF_FILE"; then
        sed -i "s/^$1=.*/$1=$2/" "$CONF_FILE"
    else
        echo "$1=$2" >> "$CONF_FILE"
    fi
}

while true; do
    notify=$(get_value NN_IDS_NOTIFY)
    discovery=$(get_value NN_IDS_DISCOVERY_MODE)
    echo "IDS Control Menu"
    echo "1) Toggle malicious packet notifications (currently: $notify)"
    echo "2) Set network discovery response (currently: $discovery)"
    echo "3) Exit"
    read -rp "Choose an option: " choice
    case "$choice" in
        1)
            if [ "$notify" = "1" ]; then
                notify=0
            else
                notify=1
            fi
            set_value NN_IDS_NOTIFY "$notify"
            echo "Notification setting updated to $notify"
            ;;
        2)
            echo "Select response mode:"
            echo "a) auto"
            echo "b) manual"
            echo "c) notify"
            echo "d) none"
            read -rp "Response choice: " resp
            case "$resp" in
                a|A) discovery="auto" ;;
                b|B) discovery="manual" ;;
                c|C) discovery="notify" ;;
                d|D) discovery="none" ;;
                *) echo "Invalid"; continue ;;
            esac
            set_value NN_IDS_DISCOVERY_MODE "$discovery"
            echo "Discovery mode set to $discovery"
            ;;
        3)
            echo "Exiting."; break ;;
        *)
            echo "Invalid option" ;;
    esac
done
