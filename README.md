# TimeChangeDetect

A Windows utility that detects system time modifications by analyzing the NTFS USN Journal.

## Overview

This tool helps detect when system time has been manually modified by analyzing the Update Sequence Number (USN) Journal in NTFS volumes. It's particularly useful for forensics and works as an alternative to the Event ID 4616 in the Event Viewer.

## How It Works

The detection mechanism relies on a fundamental property of the NTFS USN Journal: entries are sequential and each entry contains a timestamp. Here's how the detection works:

1. USN entries are always incremental - each new filesystem operation gets a higher USN than the previous one
2. Under normal circumstances, timestamps should also increment gradually
3. When someone changes the system time:
   - If the clock is set backwards:
     - We see newer USN entries with older timestamps than previous entries
     - This creates a "negative time jump"
   - If the clock is then set forward again:
     - We see a sudden large positive time jump
   - These two patterns together confirm a time manipulation event

### Example Scenario

Let's say we have these sequential USN entries:

```
USN: 1000 | Time: 14:00:00
USN: 1001 | Time: 14:00:05
USN: 1002 | Time: 13:00:00  <- Suspicious! Time went backwards
USN: 1003 | Time: 13:00:10
USN: 1004 | Time: 14:30:00  <- Time suddenly jumped forward
```

This pattern strongly indicates that:
1. The system clock was set back from 14:00 to 13:00
2. The system operated for a while with the incorrect time
3. The clock was later corrected, jumping back to the current time

## Why Use USN Journal?

While Windows Event Log (specifically Event ID 4616) is the primary method for detecting time changes, attackers often disable event logging to cover their tracks. This tool provides an alternative detection method by leveraging NTFS filesystem metadata that:

- Cannot be disabled without breaking the filesystem
- Is essential for NTFS operation

## Requirements

- Windows operating system
- Administrative privileges (to access the USN Journal)
- NTFS filesystem

## Usage

Simply run the executable as Administrator:

```bash
TimeDetect.exe
```

The program will:
1. Access the USN Journal
2. Collect and analyze the entries
3. Report any detected time manipulation patterns
