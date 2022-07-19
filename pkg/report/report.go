package report

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sad-pixel/tcpscanner/pkg/stats"
)

func createCSV(path string) error {
	csvFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not create CSV file: %w", err)
	}
	defer csvFile.Close()

	csvwriter := csv.NewWriter(csvFile)
	err = csvwriter.Write([]string{"written_at", "type", "dst_ip", "src_ip", "src_geo", "src_isp", "packet_count"})
	if err != nil {
		return fmt.Errorf("could not write CSV file headers: %w", err)
	}

	csvwriter.Flush()
	return nil
}

func GetFileHandle(path string) (*os.File, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		errCsv := createCSV(path)
		if errCsv != nil {
			return nil, errCsv
		}
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		return nil, fmt.Errorf("could not open CSV file: %w", err)
	}

	return file, nil
}

func WriteStatToCSV(w *csv.Writer, records []stats.PacketStat) error {
	writeableRecords := [][]string{}
	writtenAt := time.Now().UTC().Format(time.RFC1123)
	for _, record := range records {
		r := []string{writtenAt, record.PacketType, record.DstIP, record.SrcIP, record.SrcGeo, record.SrcISP, fmt.Sprint(record.Count)}
		writeableRecords = append(writeableRecords, r)
	}

	err := w.WriteAll(writeableRecords)
	if err != nil {
		return fmt.Errorf("could not write stats to CSV file: %w", err)
	}

	return nil
}
