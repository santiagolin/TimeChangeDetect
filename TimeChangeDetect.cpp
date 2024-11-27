#include <Windows.h>
#include <WinIoCtl.h>
#include <stdio.h>
#include <vector>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

struct UsnEntry {
    USN usnNumber;
    LONGLONG timestamp;

    bool operator<(const UsnEntry& other) const {
        return usnNumber < other.usnNumber;
    }
};

class TimeChangeDetector {
private:
    HANDLE hVolume;
    std::vector<UsnEntry> usnEntries;
    const LONGLONG MAX_ALLOWED_TIME_DIFF = 5LL * 60LL * 10000000LL;
    const size_t MAX_ENTRIES = 1000000;

    LONGLONG startingUsn;
    LONGLONG endingUsn;

    bool backwardJumpDetected = false;
    LONGLONG backwardJumpFromTime = 0;
    LONGLONG backwardJumpToTime = 0;
    LONGLONG forwardJumpFromTime = 0;
    LONGLONG forwardJumpToTime = 0;

    void printTimeAnomaly() {
        std::cout << "Time anomaly detected:\n";
        std::cout << "Backward Jump:\n";
        std::cout << " From: " << formatTimestamp(backwardJumpFromTime) << " (USN: " << getUsnByTimestamp(backwardJumpFromTime) << ")\n";
        std::cout << " To:   " << formatTimestamp(backwardJumpToTime) << " (USN: " << getUsnByTimestamp(backwardJumpToTime) << ")\n";
        std::cout << "Forward Jump:\n";
        std::cout << " From: " << formatTimestamp(forwardJumpFromTime) << " (USN: " << getUsnByTimestamp(forwardJumpFromTime) << ")\n";
        std::cout << " To:   " << formatTimestamp(forwardJumpToTime) << " (USN: " << getUsnByTimestamp(forwardJumpToTime) << ")\n";
    }

    USN getUsnByTimestamp(LONGLONG timestamp) {
        for (const auto& entry : usnEntries) {
            if (entry.timestamp == timestamp) {
                return entry.usnNumber;
            }
        }
        return 0;
    }

    std::string formatTimestamp(LONGLONG timestamp) {
        FILETIME ft;
        ft.dwHighDateTime = (DWORD)(timestamp >> 32);
        ft.dwLowDateTime = (DWORD)timestamp;

        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);

        char buffer[64];
        sprintf_s(buffer, sizeof(buffer),
            "%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

        return std::string(buffer);
    }

    void showProgress(LONGLONG current, LONGLONG total) {
        const int barWidth = 70;
        float progress = static_cast<float>(current) / total;
        if (progress > 1.0f) progress = 1.0f;
        int pos = static_cast<int>(barWidth * progress);

        std::cout << "\rProcessing: [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << std::fixed << std::setprecision(2) << (progress * 100.0) << "%"
            << " (" << current << "/" << total << " records)" << std::flush;
    }

public:
    TimeChangeDetector() : hVolume(INVALID_HANDLE_VALUE) {}

    ~TimeChangeDetector() {
        if (hVolume != INVALID_HANDLE_VALUE) {
            CloseHandle(hVolume);
        }
    }

    bool initialize() {
        hVolume = CreateFile(TEXT("\\\\.\\C:"),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hVolume == INVALID_HANDLE_VALUE) {
            printf("Error opening volume: %d\n", GetLastError());
            return false;
        }
        return true;
    }

    void collectUsnEntries() {
        USN_JOURNAL_DATA journalData;
        DWORD bytesReturned;

        if (!DeviceIoControl(hVolume,
            FSCTL_QUERY_USN_JOURNAL,
            NULL,
            0,
            &journalData,
            sizeof(journalData),
            &bytesReturned,
            NULL)) {
            printf("Error querying journal:: %d\n", GetLastError());
            return;
        }

        startingUsn = journalData.FirstUsn;
        endingUsn = journalData.NextUsn;

        printf("Reading USN Journal...\n");
        printf("Journal ID: %llu\n", journalData.UsnJournalID);
        printf("First USN: %llu\n", startingUsn);
        printf("Next USN: %llu\n", endingUsn);

        LONGLONG totalEntries = endingUsn - startingUsn;
        LONGLONG processedEntries = 0;

        READ_USN_JOURNAL_DATA_V0 readData = { 0 };
        readData.StartUsn = startingUsn;
        readData.ReasonMask = 0xFFFFFFFF;
        readData.ReturnOnlyOnClose = FALSE;
        readData.UsnJournalID = journalData.UsnJournalID;

        char buffer[64 * 1024];
        bool done = false;

        while (!done && usnEntries.size() < MAX_ENTRIES && readData.StartUsn < endingUsn) {
            if (!DeviceIoControl(hVolume,
                FSCTL_READ_USN_JOURNAL,
                &readData,
                sizeof(readData),
                buffer,
                sizeof(buffer),
                &bytesReturned,
                NULL)) {
                if (GetLastError() == ERROR_HANDLE_EOF) {
                    done = true;
                    continue;
                }
                printf("\nError querying journal: %d\n", GetLastError());
                return;
            }

            if (bytesReturned < sizeof(USN)) {
                done = true;
                continue;
            }

            DWORD readPosition = sizeof(USN);
            USN nextUsn = *((USN*)buffer);

            while (readPosition < bytesReturned) {
                PUSN_RECORD record = (PUSN_RECORD)(buffer + readPosition);

                UsnEntry entry;
                entry.usnNumber = record->Usn;
                entry.timestamp = record->TimeStamp.QuadPart;
                usnEntries.push_back(entry);

                readPosition += record->RecordLength;
            }

            processedEntries = readData.StartUsn - startingUsn;
            if (processedEntries > totalEntries) {
                processedEntries = totalEntries;
            }
            showProgress(processedEntries, totalEntries);

            readData.StartUsn = nextUsn;
        }
        std::cout << "\nDump completed. Entries processed: " << usnEntries.size() << std::endl;
    }

    void detectTimeChanges() {
        if (usnEntries.size() < 2) {
            printf("There are not enough entries to analyze\n");
            return;
        }

        printf("\nSorting entries...\n");
        std::sort(usnEntries.begin(), usnEntries.end());
        printf("Analyzing time anomalies...\n\n");

        for (size_t i = 1; i < usnEntries.size(); i++) {
            LONGLONG timeDiff = usnEntries[i].timestamp - usnEntries[i - 1].timestamp;

            if (timeDiff < -MAX_ALLOWED_TIME_DIFF && !backwardJumpDetected) {
                backwardJumpDetected = true;
                backwardJumpFromTime = usnEntries[i - 1].timestamp;
                backwardJumpToTime = usnEntries[i].timestamp;
                continue;
            }

            if (backwardJumpDetected && timeDiff > MAX_ALLOWED_TIME_DIFF) {
                forwardJumpFromTime = usnEntries[i - 1].timestamp;
                forwardJumpToTime = usnEntries[i].timestamp;
                printTimeAnomaly();
                break;
            }
        }
    }
};

int main() {
    std::cout << "https://github.com/santiagolin/TimeChangeDetect\n";
    TimeChangeDetector detector;

    if (!detector.initialize()) {
        return 1;
    }

    detector.collectUsnEntries();
    detector.detectTimeChanges();

    printf("\nPress enter to exit...");
    getchar();
    return 0;
}