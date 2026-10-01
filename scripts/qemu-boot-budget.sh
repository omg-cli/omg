#!/usr/bin/env bash
# Internal phase contract shared by the host driver, boot.sh and clone caller.
# Readiness is an absolute deadline, not a retry count times nominal SSH time.
SSH_WAIT_BUDGET=1680
SSH_ATTEMPT_TIMEOUT=12
SSH_KILL_GRACE=2
SSH_RETRY_DELAY=2
BOOT_SETUP_TIMEOUT=180
BOOT_CLOUD_INIT_TIMEOUT=250
BOOT_IDENTITY_TIMEOUT=15
BOOT_PHASE_KILL_GRACE=2
BOOT_OVERHEAD=30
# cloud-init has 180+5 and 60+5 second commands; its wrapper reserves that 250.
CLONE_BOOT_TIMEOUT=$(( BOOT_SETUP_TIMEOUT + BOOT_PHASE_KILL_GRACE + SSH_WAIT_BUDGET + BOOT_CLOUD_INIT_TIMEOUT + BOOT_PHASE_KILL_GRACE + BOOT_IDENTITY_TIMEOUT + BOOT_PHASE_KILL_GRACE + BOOT_OVERHEAD ))
# Initial boot adds reboot readiness and five bounded commands: timer enable,
# SSH enable, old boot ID, reboot request, and final service verification.
BOOT_TIMEOUT=$(( CLONE_BOOT_TIMEOUT + SSH_WAIT_BUDGET + 5 * (SSH_ATTEMPT_TIMEOUT + SSH_KILL_GRACE) ))
