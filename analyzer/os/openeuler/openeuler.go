package openeuler

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&openeulerOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"etc/os-release",
}

type openeulerOSAnalyzer struct{}

func (a openeulerOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	openeulerName := ""
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"openEuler") {
			openeulerName = aos.OpenEuler
			continue
		}

		if openeulerName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: openeulerName,
					Name:   strings.TrimSpace(line[12 : len(line)-1]),
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("openeuler: %w", aos.AnalyzeOSError)
}

func (a openeulerOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a openeulerOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeOpenEuler
}

func (a openeulerOSAnalyzer) Version() int {
	return version
}
