package services

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aws/smithy-go"
)

type apiFailure struct {
	service string
	op      string
	code    string
	regions map[string]bool
	count   int
}

var (
	failures     = map[string]*apiFailure{}
	failureOrder []string
)

func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return "RequestFailed"
}

func warn(service, op, region string, err error) {
	if err == nil {
		return
	}

	code := errorCode(err)
	key := service + "|" + op + "|" + code

	f, seen := failures[key]
	if !seen {
		f = &apiFailure{
			service: service,
			op:      op,
			code:    code,
			regions: map[string]bool{},
		}
		failures[key] = f
		failureOrder = append(failureOrder, key)
	}

	f.count++
	if region != "" {
		f.regions[region] = true
	}

	if !seen {
		where := ""
		if region != "" {
			where = " in " + region
		}
		fmt.Fprintf(os.Stderr, "\t\t[!] %s %s failed%s: %s\n", service, op, where, err)
	}
}

func FlushWarnings() {
	if len(failureOrder) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n[!] %d API failure(s) during enumeration, results may be incomplete:\n", len(failureOrder))

	for _, key := range failureOrder {
		f := failures[key]

		detail := fmt.Sprintf("%d call(s)", f.count)
		if len(f.regions) > 0 {
			regions := make([]string, 0, len(f.regions))
			for r := range f.regions {
				regions = append(regions, r)
			}
			sort.Strings(regions)
			detail += ", regions: " + strings.Join(regions, ", ")
		}

		fmt.Fprintf(os.Stderr, "\t%s %s: %s (%s)\n", f.service, f.op, f.code, detail)
	}
}
