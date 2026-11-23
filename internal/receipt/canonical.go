package receipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical returns the bytes that are hashed and signed. Version 1 retains
// its original struct-order encoding; version 2 sorts object keys and uses JCS
// string escaping. Receipt numbers are integers, so floats fail closed rather
// than implementing the ES6 number formatting required by full RFC 8785.
func (r Receipt) Canonical() ([]byte, error) {
	if r.Version == LegacyVersion {
		return json.Marshal(r)
	}
	fields := map[string]any{
		"argv":            r.Argv,
		"ended_at":        r.EndedAt,
		"engine":          r.Engine,
		"exit_code":       r.ExitCode,
		"output_bytes":    r.OutputBytes,
		"output_sha256":   r.OutputSHA256,
		"permission_mode": r.PermissionMode,
		"policy_decision": r.PolicyDecision,
		"policy_sha256":   r.PolicySHA256,
		"prev_hash":       r.PrevHash,
		"prompt_sha256":   r.PromptSHA256,
		"public_key":      r.PublicKey,
		"seq":             r.Seq,
		"started_at":      r.StartedAt,
		"version":         r.Version,
	}
	if r.PolicyReason != "" {
		fields["policy_reason"] = r.PolicyReason
	}
	return canonicalJSON(fields)
}

func canonicalJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendCanonical(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendCanonical(out *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(value))
	case string:
		return appendJSONString(out, value)
	case int:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case uint64:
		out.WriteString(strconv.FormatUint(value, 10))
	case []string:
		if value == nil {
			out.WriteString("null")
			return nil
		}
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendJSONString(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendJSONString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendCanonical(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case float32, float64:
		return fmt.Errorf("canonical JSON does not support floats")
	default:
		return fmt.Errorf("canonical JSON does not support %T", v)
	}
	return nil
}

func appendJSONString(out *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("canonical JSON string is not valid UTF-8")
	}
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

func utf16Less(a, b string) bool {
	aa, bb := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return len(aa) < len(bb)
}
