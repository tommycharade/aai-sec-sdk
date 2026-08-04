package provider

func textField(item map[string]any, key string) string {
	value, _ := item[key].(string)
	return value
}

func boolField(item map[string]any, key string) bool {
	value, _ := item[key].(bool)
	return value
}

func intField(item map[string]any, key string) int64 {
	switch value := item[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	default:
		return 0
	}
}

func stringSliceField(item map[string]any, key string) []string {
	values, _ := item[key].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
