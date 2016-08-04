// Package govalidator is package of validators and sanitizers for strings, structs and collections.
package govalidator

import (
	"time"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"unicode"
	"unicode/utf8"
)

var fieldsRequiredByDefault bool

// SetFieldsRequiredByDefault causes validation to fail when struct fields
// do not include validations or are not explicitly marked as exempt (using `valid:"-"` or `valid:"email,optional"`).
// This struct definition will fail govalidator.ValidateStruct() (and the field values do not matter):
//     type exampleStruct struct {
//         Name  string ``
//         Email string `valid:"email"`
// This, however, will only fail when Email is empty or an invalid email address:
//     type exampleStruct2 struct {
//         Name  string `valid:"-"`
//         Email string `valid:"email"`
// Lastly, this will only fail when Email is an invalid email address but not when it's empty:
//     type exampleStruct2 struct {
//         Name  string `valid:"-"`
//         Email string `valid:"email,optional"`
func SetFieldsRequiredByDefault(value bool) {
	fieldsRequiredByDefault = value
}

// IsEmail check if the string is an email.
func IsEmail(str string) bool {
	// TODO uppercase letters are not supported
	return rxEmail.MatchString(str)
}

// IsURL check if the string is an URL.
func IsURL(str string) bool {
	if str == "" || len(str) >= 2083 || len(str) <= 3 || strings.HasPrefix(str, ".") {
		return false
	}
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	if strings.HasPrefix(u.Host, ".") {
		return false
	}
	if u.Host == "" && (u.Path != "" && !strings.Contains(u.Path, ".")) {
		return false
	}
	return rxURL.MatchString(str)

}

// IsRequestURL check if the string rawurl, assuming
// it was recieved in an HTTP request, is a valid
// URL confirm to RFC 3986
func IsRequestURL(rawurl string) bool {
	url, err := url.ParseRequestURI(rawurl)
	if err != nil {
		return false //Couldn't even parse the rawurl
	}
	if len(url.Scheme) == 0 {
		return false //No Scheme found
	}
	return true
}

// IsRequestURI check if the string rawurl, assuming
// it was recieved in an HTTP request, is an
// absolute URI or an absolute path.
func IsRequestURI(rawurl string) bool {
	_, err := url.ParseRequestURI(rawurl)
	return err == nil
}

// IsAlpha check if the string contains only letters (a-zA-Z). Empty string is valid.
func IsAlpha(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxAlpha.MatchString(str)
}

//IsUTFLetter check if the string contains only unicode letter characters.
//Similar to IsAlpha but for all languages. Empty string is valid.
func IsUTFLetter(str string) bool {
	if IsNull(str) {
		return true
	}

	for _, c := range str {
		if !unicode.IsLetter(c) {
			return false
		}
	}
	return true

}

// IsAlphanumeric check if the string contains only letters and numbers. Empty string is valid.
func IsAlphanumeric(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxAlphanumeric.MatchString(str)
}

// IsUTFLetterNumeric check if the string contains only unicode letters and numbers. Empty string is valid.
func IsUTFLetterNumeric(str string) bool {
	if IsNull(str) {
		return true
	}
	for _, c := range str {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) { //letters && numbers are ok
			return false
		}
	}
	return true

}

// IsNumeric check if the string contains only numbers. Empty string is valid.
func IsNumeric(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxNumeric.MatchString(str)
}

// IsUTFNumeric check if the string contains only unicode numbers of any kind.
// Numbers can be 0-9 but also Fractions ¾,Roman Ⅸ and Hangzhou 〩. Empty string is valid.
func IsUTFNumeric(str string) bool {
	if IsNull(str) {
		return true
	}
	if strings.IndexAny(str, "+-") > 0 {
		return false
	}
	if len(str) > 1 {
		str = strings.TrimPrefix(str, "-")
		str = strings.TrimPrefix(str, "+")
	}
	for _, c := range str {
		if unicode.IsNumber(c) == false { //numbers && minus sign are ok
			return false
		}
	}
	return true

}

// IsUTFDigit check if the string contains only unicode radix-10 decimal digits. Empty string is valid.
func IsUTFDigit(str string) bool {
	if IsNull(str) {
		return true
	}
	if strings.IndexAny(str, "+-") > 0 {
		return false
	}
	if len(str) > 1 {
		str = strings.TrimPrefix(str, "-")
		str = strings.TrimPrefix(str, "+")
	}
	for _, c := range str {
		if !unicode.IsDigit(c) { //digits && minus sign are ok
			return false
		}
	}
	return true

}

// IsHexadecimal check if the string is a hexadecimal number.
func IsHexadecimal(str string) bool {
	return rxHexadecimal.MatchString(str)
}

// IsHexcolor check if the string is a hexadecimal color.
func IsHexcolor(str string) bool {
	return rxHexcolor.MatchString(str)
}

// IsRGBcolor check if the string is a valid RGB color in form rgb(RRR, GGG, BBB).
func IsRGBcolor(str string) bool {
	return rxRGBcolor.MatchString(str)
}

// IsLowerCase check if the string is lowercase. Empty string is valid.
func IsLowerCase(str string) bool {
	if IsNull(str) {
		return true
	}
	return str == strings.ToLower(str)
}

// IsUpperCase check if the string is uppercase. Empty string is valid.
func IsUpperCase(str string) bool {
	if IsNull(str) {
		return true
	}
	return str == strings.ToUpper(str)
}

// IsInt check if the string is an integer. Empty string is valid.
func IsInt(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxInt.MatchString(str)
}

// IsFloat check if the string is a float.
func IsFloat(str string) bool {
	return str != "" && rxFloat.MatchString(str)
}

// IsDivisibleBy check if the string is a number that's divisible by another.
// If second argument is not valid integer or zero, it's return false.
// Otherwise, if first argument is not valid integer or zero, it's return true (Invalid string converts to zero).
func IsDivisibleBy(str, num string) bool {
	f, _ := ToFloat(str)
	p := int64(f)
	q, _ := ToInt(num)
	if q == 0 {
		return false
	}
	return (p == 0) || (p%q == 0)
}

// IsNull check if the string is null.
func IsNull(str string) bool {
	return len(str) == 0
}

// IsByteLength check if the string's length (in bytes) falls in a range.
func IsByteLength(str string, min, max int) bool {
	return len(str) >= min && len(str) <= max
}

// IsUUIDv3 check if the string is a UUID version 3.
func IsUUIDv3(str string) bool {
	return rxUUID3.MatchString(str)
}

// IsUUIDv4 check if the string is a UUID version 4.
func IsUUIDv4(str string) bool {
	return rxUUID4.MatchString(str)
}

// IsUUIDv5 check if the string is a UUID version 5.
func IsUUIDv5(str string) bool {
	return rxUUID5.MatchString(str)
}

// IsUUID check if the string is a UUID (version 3, 4 or 5).
func IsUUID(str string) bool {
	return rxUUID.MatchString(str)
}

// IsCreditCard check if the string is a credit card.
func IsCreditCard(str string) bool {
	r, _ := regexp.Compile("[^0-9]+")
	sanitized := r.ReplaceAll([]byte(str), []byte(""))
	if !rxCreditCard.MatchString(string(sanitized)) {
		return false
	}
	var sum int64
	var digit string
	var tmpNum int64
	var shouldDouble bool
	for i := len(sanitized) - 1; i >= 0; i-- {
		digit = string(sanitized[i:(i + 1)])
		tmpNum, _ = ToInt(digit)
		if shouldDouble {
			tmpNum *= 2
			if tmpNum >= 10 {
				sum += ((tmpNum % 10) + 1)
			} else {
				sum += tmpNum
			}
		} else {
			sum += tmpNum
		}
		shouldDouble = !shouldDouble
	}

	if sum%10 == 0 {
		return true
	}
	return false
}

// IsISBN10 check if the string is an ISBN version 10.
func IsISBN10(str string) bool {
	return IsISBN(str, 10)
}

// IsISBN13 check if the string is an ISBN version 13.
func IsISBN13(str string) bool {
	return IsISBN(str, 13)
}

// IsISBN check if the string is an ISBN (version 10 or 13).
// If version value is not equal to 10 or 13, it will be check both variants.
func IsISBN(str string, version int) bool {
	r, _ := regexp.Compile("[\\s-]+")
	sanitized := r.ReplaceAll([]byte(str), []byte(""))
	var checksum int32
	var i int32
	if version == 10 {
		if !rxISBN10.MatchString(string(sanitized)) {
			return false
		}
		for i = 0; i < 9; i++ {
			checksum += (i + 1) * int32(sanitized[i]-'0')
		}
		if sanitized[9] == 'X' {
			checksum += 10 * 10
		} else {
			checksum += 10 * int32(sanitized[9]-'0')
		}
		if checksum%11 == 0 {
			return true
		}
		return false
	} else if version == 13 {
		if !rxISBN13.MatchString(string(sanitized)) {
			return false
		}
		factor := []int32{1, 3}
		for i = 0; i < 12; i++ {
			checksum += factor[i%2] * int32(sanitized[i]-'0')
		}
		if (int32(sanitized[12]-'0'))-((10-(checksum%10))%10) == 0 {
			return true
		}
		return false
	}
	return IsISBN(str, 10) || IsISBN(str, 13)
}

// IsJSON check if the string is valid JSON (note: uses json.Unmarshal).
func IsJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}

// IsMultibyte check if the string contains one or more multibyte chars. Empty string is valid.
func IsMultibyte(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxMultibyte.MatchString(str)
}

// IsASCII check if the string contains ASCII chars only. Empty string is valid.
func IsASCII(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxASCII.MatchString(str)
}

// IsPrintableASCII check if the string contains printable ASCII chars only. Empty string is valid.
func IsPrintableASCII(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxPrintableASCII.MatchString(str)
}

// IsFullWidth check if the string contains any full-width chars. Empty string is valid.
func IsFullWidth(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxFullWidth.MatchString(str)
}

// IsHalfWidth check if the string contains any half-width chars. Empty string is valid.
func IsHalfWidth(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxHalfWidth.MatchString(str)
}

// IsVariableWidth check if the string contains a mixture of full and half-width chars. Empty string is valid.
func IsVariableWidth(str string) bool {
	if IsNull(str) {
		return true
	}
	return rxHalfWidth.MatchString(str) && rxFullWidth.MatchString(str)
}

// IsBase64 check if a string is base64 encoded.
func IsBase64(str string) bool {
	return rxBase64.MatchString(str)
}

// IsFilePath check is a string is Win or Unix file path and returns it's type.
func IsFilePath(str string) (bool, int) {
	if rxWinPath.MatchString(str) {
		//check windows path limit see:
		//  http://msdn.microsoft.com/en-us/library/aa365247(VS.85).aspx#maxpath
		if len(str[3:]) > 32767 {
			return false, Win
		}
		return true, Win
	} else if rxUnixPath.MatchString(str) {
		return true, Unix
	}
	return false, Unknown
}

// IsDataURI checks if a string is base64 encoded data URI such as an image
func IsDataURI(str string) bool {
	dataURI := strings.Split(str, ",")
	if !rxDataURI.MatchString(dataURI[0]) {
		return false
	}
	return IsBase64(dataURI[1])
}

// IsISO3166Alpha2 checks if a string is valid two-letter country code
func IsISO3166Alpha2(str string) bool {
	for _, entry := range ISO3166List {
		if str == entry.Alpha2Code {
			return true
		}
	}
	return false
}

// IsISO3166Alpha3 checks if a string is valid three-letter country code
func IsISO3166Alpha3(str string) bool {
	for _, entry := range ISO3166List {
		if str == entry.Alpha3Code {
			return true
		}
	}
	return false
}

// IsDNSName will validate the given string as a DNS name
func IsDNSName(str string) bool {
	if str == "" || len(strings.Replace(str, ".", "", -1)) > 255 {
		// constraints already violated
		return false
	}
	return rxDNSName.MatchString(str)
}

// IsDialString validates the given string for usage with the various Dial() functions
func IsDialString(str string) bool {

	if h, p, err := net.SplitHostPort(str); err == nil && h != "" && p != "" && (IsDNSName(h) || IsIP(h)) && IsPort(p) {
		return true
	}

	return false
}

// IsIP checks if a string is either IP version 4 or 6.
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

// IsPort checks if a string represents a valid port
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

// IsIPv4 check if the string is an IP version 4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 check if the string is an IP version 6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

// IsMAC check if a string is valid MAC address.
// Possible MAC formats:
// 01:23:45:67:89:ab
// 01:23:45:67:89:ab:cd:ef
// 01-23-45-67-89-ab
// 01-23-45-67-89-ab-cd-ef
// 0123.4567.89ab
// 0123.4567.89ab.cdef
func IsMAC(str string) bool {
	_, err := net.ParseMAC(str)
	return err == nil
}

// IsHost checks if the string is a valid IP (both v4 and v6) or a valid DNS name
func IsHost(str string) bool {
	return IsIP(str) || IsDNSName(str)
}

// IsMongoID check if the string is a valid hex-encoded representation of a MongoDB ObjectId.
func IsMongoID(str string) bool {
	return rxHexadecimal.MatchString(str) && (len(str) == 24)
}

// IsLatitude check if a string is valid latitude.
func IsLatitude(str string) bool {
	return rxLatitude.MatchString(str)
}

// IsLongitude check if a string is valid longitude.
func IsLongitude(str string) bool {
	return rxLongitude.MatchString(str)
}

// ValidateStruct use tags for fields.
// result will be equal to `false` if there are any errors.
func ValidateStruct(s interface{}) (bool, error) {
	if s == nil {
		return true, nil
	}
	result := true
	var err error
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Interface || val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	// we only accept structs
	if val.Kind() != reflect.Struct {
		return false, fmt.Errorf("function only accepts structs; got %s", val.Kind())
	}
	var errs Errors
	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		typeField := val.Type().Field(i)
		if typeField.PkgPath != "" {
			continue // Private field
		}
		resultField, err2 := typeCheck(valueField, typeField, val)
		if err2 != nil {
			errs = append(errs, err2)
		}
		result = result && resultField
	}
	if len(errs) > 0 {
		err = errs
	}
	return result, err
}

// parseTagIntoMap parses a struct tag `valid:required~Some error message,length(2|3)` into map[string]string{"required": "Some error message", "length(2|3)": ""}
func parseTagIntoMap(tag string) tagOptionsMap {
	optionsMap := make(tagOptionsMap)
	options := strings.SplitN(tag, ",", -1)
	for _, option := range options {
		validationOptions := strings.Split(option, "~")
		if !isValidTag(validationOptions[0]) {
			continue
		}
		if len(validationOptions) == 2 {
			optionsMap[validationOptions[0]] = validationOptions[1]
		} else {
			optionsMap[validationOptions[0]] = ""
		}
	}
	return optionsMap
}

func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		default:
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				return false
			}
		}
	}
	return true
}

// IsSSN will validate the given string as a U.S. Social Security Number
func IsSSN(str string) bool {
	if str == "" || len(str) != 11 {
		return false
	}
	return rxSSN.MatchString(str)
}

// IsSemver check if string is valid semantic version
func IsSemver(str string) bool {
	return rxSemver.MatchString(str)
}

// IsDurtion check if string is valid duration string
// such as "300ms", "-1.5h" or "2h45m". Valid time units 
// are "ns", "us" (or "µs"), "ms", "s", "m", "h".
// ref https://golang.org/pkg/time/#ParseDuration
func IsDuration(str string) bool {
	_, err := time.ParseDuration(str)
	return err == nil
}

// check if valid China mobile phone number
func IsChinaMobile(str string) bool {
	reg := regexp.MustCompile(`^1[0-9]{10}$`)
	return reg.FindString(str) == str
}


// check if valid China mobile phone number
func IsChinaIdCard(str string) bool {
	reg := regexp.MustCompile(`(^[0-9]{6}[1|2][0-9]{3}[01][0-9][0-3][0-9]{4}([0-9]|X)$)`)
	if reg.FindString(str) == str {
		valid, _ := validateChinaId(str)
		return valid
	}
	return false
}

// china id card is composed from 
// 1. address code : 6 digits
// 2. birthday 8 digits
// 3. swq number 3 digits, even for female, odd for male
// 4. vefification code, 1 digits
func validateChinaId(str string) (isvalid bool, expected string) {
    weight := []int {7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2}    //十七位数字本体码权重
    validate := []byte{ '1','0','X','9','8','7','6','5','4','3','2'}    //mod11,对应校验码字符值    
     
    sum := 0
    mode := 0
	for i, v := range []byte(str)[:17] {
		c := v - '0'
        sum = sum + int(c) * weight[i];
    }
    mode = sum % 11;
    return validate[mode] == str[17], string(validate[mode])
}

// IsDatetime check if the string is valid date time format
// ref https://golang.org/pkg/time/#Parse for how to specify the date time format
// (strings of how to present the time 'Mon Jan 2 15:04:05 -0700 MST 2006' should be given
// multiple format is allowed by sperarator "|"
func IsDatetime(str interface{}, params ...string) bool {
	if len(params) > 0 {
		f := params[0]
		f = strings.TrimSpace(f)
		f = strings.TrimPrefix(f, "datetime(")
		f = strings.TrimSuffix(f, ")")
		fs := strings.Split(f, "|")
		for _, v := range fs {
			if _, err := time.Parse(v, str.(string)); err == nil {
				return true
			}
		}
	}
	
	return false
}

// ByteLength check string's length
func ByteLength(str interface{}, params ...string) bool {
	if len(params) == 2 {
		min, _ := ToInt(params[0])
		max, _ := ToInt(params[1])
		return len(str.(string)) >= int(min) && len(str.(string)) <= int(max)
	}

	return false
}

// StringMatches checks if a string matches a given pattern.
func StringMatches(s interface{}, params ...string) bool {
	if len(params) > 1 {
		pattern := params[1]
		return Matches(s.(string), pattern)
	}
	return false
}

// StringLength check string's length (including multi byte strings)
func StringLength(str interface{}, params ...string) bool {

	if len(params) == 2 {
		strLength := utf8.RuneCountInString(str.(string))
		min, _ := ToInt(params[0])
		max, _ := ToInt(params[1])
		return strLength >= int(min) && strLength <= int(max)
	}

	return false
}

// ByteLength check string's length
func LengthV(str interface{}, params ...string) bool {
	if len(params) > 2 {
		min, _ := ToInt(params[1])
		max, _ := ToInt(params[2])
		v := reflect.ValueOf(str)
		switch v.Kind() {
			case reflect.String:
				s := str.(string)
				return len(s) >= int(min) && len(s) <= int(max)
			case reflect.Slice, reflect.Array:
				return int64(v.Len()) >= int64(min) && int64(v.Len()) <= int64(max)
		}
	}

	return false
}

// StringMatches checks if a string matches a given pattern.
func StringMatchesV(s interface{}, params ...string) bool {
	if len(params) > 1 {
		pattern := params[1]
		return Matches(s.(string), pattern)
	}
	return false
}

// StringLength check string's length (including multi byte strings)
func StringLengthV(str interface{},  params ...string) bool {

	if len(params) > 2 {
		strLength := utf8.RuneCountInString(str.(string))
		min, _ := ToInt(params[1])
		max, _ := ToInt(params[2])
		return strLength >= int(min) && strLength <= int(max)
	}

	return false
}

// Range check number's value is between the given range values 
// can be represented as [ for <=, ( for <, ] for >=, ) for >
func Range(v interface{}, params ...string) bool {
	if len(params) > 4 {
		q1 := params[1]
		q2 := params[4]
		switch v.(type) {
			case int:
				i := v.(int)
				min, _ := strconv.Atoi(params[2])
				max, _ := strconv.Atoi(params[3])
				return ((q1 == "[" && i >= min) ||
						(q1 == "(" && i > min) )&& 
					   ((q2 == "]" && i <= max) ||
						(q2 == ")" && i < max))
			case float32, float64:
				var i float64
				switch v.(type) {
					case float32:
						i = float64(v.(float32))
				    case float64:
						i = v.(float64)
				}
				min, _ := strconv.ParseFloat(params[2], 64)
				max, _ := strconv.ParseFloat(params[3], 64)
				return ((q1 == "[" && i >= min) ||
						(q1 == "(" && i > min) )&& 
					   ((q2 == "]" && i <= max) ||
						(q2 == ")" && i < max))
			default:
				return false
		}
	}

	return false
}

func Enum(v interface{}, params ...string) bool {
	if len(params) > 0 {
		matched := strings.ToLower(params[0])
		e := strings.TrimPrefix(matched, "enum(")
		e = strings.TrimSuffix(e, ")")
		items := strings.Split(e, "|")
		
		ary := reflect.ValueOf(v)

		for i := 0; i < ary.Len(); i++ {
			s := fmt.Sprint(ary.Index(i).Interface())
			match := false
			for _, w := range items {
				if s == w {
					match = true
					break
				}
			}
			if match == false {
				return false
			}
		}
		return true
	}
	
	return false
}

func checkRequired(v reflect.Value, t reflect.StructField, options tagOptionsMap) (bool, error) {
	if requiredOption, isRequired := options["required"]; isRequired {
		if len(requiredOption) > 0 {
			return false, Error{t.Name, fmt.Errorf(requiredOption), true}
		}
		return false, Error{t.Name, fmt.Errorf("non zero value required"), false}
	} else if _, isOptional := options["optional"]; fieldsRequiredByDefault && !isOptional {
		return false, Error{t.Name, fmt.Errorf("All fields are required to at least have one validation defined"), false}
	}
	// not required and empty is valid
	return true, nil
}

func TypeCheckByString(v interface{}, t_Name string, tag string) (bool, error) {
	t := reflect.StructField{}
	t.Name = t_Name
	return typeCheck(reflect.ValueOf(v), t, reflect.ValueOf(nil), tag)
}

func typeCheck(v reflect.Value, t reflect.StructField, o reflect.Value, tags...string) (bool, error) {
	if !v.IsValid() {
		return false, nil
	}

	var tag string
	if len(tags) == 0 {
		tag = t.Tag.Get(tagName)
	} else {
		tag = tags[0]
		for i := 1; i < len(tags); i++ {
			tag += "," + tags[i]
		}
	}

	// Check if the field should be ignored
	switch tag {
	case "":
		if !fieldsRequiredByDefault {
			return true, nil
		}
		return false, Error{t.Name, fmt.Errorf("All fields are required to at least have one validation defined"), false}
	case "-":
		return true, nil
	}

	options := parseTagIntoMap(tag)
	
	// handling custom type validators
	// IN: options, validatorName, v, o
	// OUT: customTypeErrors, customTypeValidatorsExist
	var customTypeErrors Errors
	var customTypeValidatorsExist bool
	for validatorName, customErrorMessage := range options {
		if validatefunc, ok := CustomTypeTagMap.Get(validatorName); ok {
			customTypeValidatorsExist = true
			if result := validatefunc(v.Interface(), o.Interface()); !result {
				if len(customErrorMessage) > 0 {
					customTypeErrors = append(customTypeErrors, Error{Name: t.Name, Err: fmt.Errorf(customErrorMessage), CustomErrorMessageExists: true})
					continue
				}
				customTypeErrors = append(customTypeErrors, Error{Name: t.Name, Err: fmt.Errorf("%s does not validate as %s", fmt.Sprint(v), validatorName), CustomErrorMessageExists: false})
			}
		}
	}
	if customTypeValidatorsExist {
		if len(customTypeErrors.Errors()) > 0 {
			return false, customTypeErrors
		}
		return true, nil
	}

	// check empty
	// IN: v, t, options
	if isEmptyValue(v) {
		// an empty value is not validated, check only required
		return checkRequired(v, t, options)
	}

	// begin of main validation
	// IN: v, options, ParamTagRegexMap, ParamTagMap, TagMap
	// OUT: validation result
	
	return validateField(v, t, v, options)
}

func validateField(v reflect.Value, t reflect.StructField, o reflect.Value, options tagOptionsMap) (bool, error) {
	switch v.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.String:
		// for each tag option check the map of validator functions
		for validator, customErrorMessage := range options {
			var negate bool
			customMsgExists := (len(customErrorMessage) > 0)
			// Check wether the tag looks like '!something' or 'something'
			if validator[0] == '!' {
				validator = string(validator[1:])
				negate = true
			}

			// Check for param validators
			for key, value := range ParamTagRegexMap {
				ps := value.FindStringSubmatch(validator)
				if len(ps) > 0 {
					if validatefunc, ok := ParamTagMap[key]; ok {
						var field interface{}

						field = v.Interface()
						if result := validatefunc(field, ps[0:]...); (!result && !negate) || (result && negate) {
							var err error
							if !negate {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%v does not validate as %s", field, validator)
								}

							} else {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%s does validate as %s", field, validator)
								}
							}
							return false, Error{t.Name, err, customMsgExists}
						}
					}
				}
			}

			if validatefunc, ok := TagMap[validator]; ok {		
				switch v.Kind() {
				case reflect.String, reflect.Int:
					field := fmt.Sprint(v) // make value into string, then validate with regex
					if result := validatefunc(field); !result && !negate || result && negate {
						var err error

						if !negate {
							if customMsgExists {
								err = fmt.Errorf(customErrorMessage)
							} else {
								err = fmt.Errorf("%s does not validate as %s", field, validator)
							}
						} else {
							if customMsgExists {
								err = fmt.Errorf(customErrorMessage)
							} else {
								err = fmt.Errorf("%s does validate as %s", field, validator)
							}
						}
						return false, Error{t.Name, err, customMsgExists}
					}
				default:
					//Not Yet Supported Types (Fail here!)
					err := fmt.Errorf("Validator %s doesn't support kind %s for value %v", validator, v.Kind(), v)
					return false, Error{t.Name, err, false}
				}
			}
		}
		return true, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return false, &UnsupportedTypeError{v.Type()}
		}
		var sv stringValues
		sv = v.MapKeys()
		sort.Sort(sv)
		result := true
		for _, k := range sv {
			resultItem, err := ValidateStruct(v.MapIndex(k).Interface())
			if err != nil {
				return false, err
			}
			result = result && resultItem
		}
		return result, nil
	case reflect.Slice, reflect.Array:
		for validator, customErrorMessage := range options {
			var negate bool
			customMsgExists := (len(customErrorMessage) > 0)
			// Check wether the tag looks like '!something' or 'something'
			if validator[0] == '!' {
				validator = string(validator[1:])
				negate = true
			}

			// Check for param validators
			for key, value := range ParamTagRegexMap {
				ps := value.FindStringSubmatch(validator)
				if len(ps) > 0 {
					if validatefunc, ok := ParamTagMap[key]; ok {
						
						field := v.Interface()
						if result := validatefunc(field, ps[0:]...); (!result && !negate) || (result && negate) {
							var err error
							if !negate {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%v does not validate as %s", field, validator)
								}

							} else {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%s does validate as %s", field, validator)
								}
							}
							return false, Error{t.Name, err, customMsgExists}
						}
					}
				}
			}

			// check for non parametered validators
			if validatefunc, ok := TagMap[validator]; ok {
				switch v.Index(0).Kind() {
				case reflect.String, reflect.Int, reflect.Int32,reflect.Int64:
					for i := 0; i < v.Len(); i++ {
						field := fmt.Sprint(v.Index(i)) // make value into string, then validate with regex
						if result := validatefunc(field); !result && !negate || result && negate {
							var err error
	
							if !negate {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%s does not validate as %s", field, validator)
								}
							} else {
								if customMsgExists {
									err = fmt.Errorf(customErrorMessage)
								} else {
									err = fmt.Errorf("%s does validate as %s", field, validator)
								}
							}
							return false, Error{t.Name, err, customMsgExists}
						}
					}
				default:
					//Not Yet Supported Types (Fail here!)
					err := fmt.Errorf("Validator %s doesn't support kind %s for value %v", validator, v.Kind(), v)
					return false, Error{t.Name, err, false}
				}
			}
		}

		result := true
		for i := 0; i < v.Len(); i++ {
			var resultItem bool
			var err error
			if v.Index(i).Kind() != reflect.Struct {
				resultItem, err = typeCheck(v.Index(i), t, o)
				if err != nil {
					return false, err
				}
			} else {
				resultItem, err = ValidateStruct(v.Index(i).Interface())
				if err != nil {
					return false, err
				}
			}
			result = result && resultItem
		}
		return result, nil
	case reflect.Interface:
		// If the value is an interface then encode its element
		if v.IsNil() {
			return true, nil
		}
		return ValidateStruct(v.Interface())
	case reflect.Ptr:
		// If the value is a pointer then check its element
		if v.IsNil() {
			return true, nil
		}
		return typeCheck(v.Elem(), t, o)
	case reflect.Struct:
		return ValidateStruct(v.Interface())
	default:
		return false, &UnsupportedTypeError{v.Type()}
	}
}



func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String, reflect.Array:
		return v.Len() == 0
	case reflect.Map, reflect.Slice:
		return v.Len() == 0 || v.IsNil()
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}

	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}

// ErrorByField returns error for specified field of the struct
// validated by ValidateStruct or empty string if there are no errors
// or this field doesn't exists or doesn't have any errors.
func ErrorByField(e error, field string) string {
	if e == nil {
		return ""
	}
	return ErrorsByField(e)[field]
}

// ErrorsByField returns map of errors of the struct validated
// by ValidateStruct or empty map if there are no errors.
func ErrorsByField(e error) map[string]string {
	m := make(map[string]string)
	if e == nil {
		return m
	}
	// prototype for ValidateStruct

	switch e.(type) {
	case Error:
		m[e.(Error).Name] = e.(Error).Err.Error()
	case Errors:
		for _, item := range e.(Errors).Errors() {
			n := ErrorsByField(item)
			for k, v := range n {
				m[k] = v
			}
		}
	}

	return m
}

// Error returns string equivalent for reflect.Type
func (e *UnsupportedTypeError) Error() string {
	return "validator: unsupported type: " + e.Type.String()
}

func (sv stringValues) Len() int           { return len(sv) }
func (sv stringValues) Swap(i, j int)      { sv[i], sv[j] = sv[j], sv[i] }
func (sv stringValues) Less(i, j int) bool { return sv.get(i) < sv.get(j) }
func (sv stringValues) get(i int) string   { return sv[i].String() }
