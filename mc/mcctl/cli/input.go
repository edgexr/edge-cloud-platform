package cli

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/mitchellh/mapstructure"
	yaml "github.com/mobiledgex/yaml/v2"
	"golang.org/x/crypto/ssh/terminal"
)

type Input struct {
	// Required argument names
	RequiredArgs []string
	// Alias argument names, format is alias=real
	AliasArgs []string
	// Password arg will prompt for password if not in args list
	PasswordArg string
	// Verify password if prompting
	VerifyPassword bool
	// Mapstructure DecodeHook functions
	DecodeHook mapstructure.DecodeHookFunc
	// Allow extra args that were not mapped to target object.
	AllowUnused bool
}

// Args are format name=val, where name could be a hierarchical name
// separated by ., i.e. appdata.key.name.
// Arg names should be all lowercase.
// NOTE: arrays and maps not supported yet.
func (s *Input) ParseArgs(args []string, obj interface{}) (map[string]interface{}, error) {
	dat := make(map[string]interface{})

	// resolve aliases first
	aliases := make(map[string]string)
	reals := make(map[string]string)
	if s.AliasArgs != nil {
		for _, alias := range s.AliasArgs {
			ar := strings.SplitN(alias, "=", 2)
			if len(ar) != 2 {
				fmt.Printf("skipping invalid alias %s\n", alias)
				continue
			}
			aliases[ar[0]] = ar[1]
			reals[ar[1]] = ar[0]
		}
	}
	required := make(map[string]struct{})
	if s.RequiredArgs != nil {
		for _, req := range s.RequiredArgs {
			req = resolveAlias(req, aliases)
			required[req] = struct{}{}
		}
	}

	// create generic data map from args
	passwordFound := false
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return dat, fmt.Errorf("arg \"%s\" not name=val format", arg)
		}
		key := resolveAlias(kv[0], aliases)
		delete(required, key)
		setKeyVal(dat, key, kv[1])
		if key == s.PasswordArg {
			passwordFound = true
		}
	}

	// ensure required args are present
	if len(required) != 0 {
		missing := []string{}
		for k, _ := range required {
			k = resolveAlias(k, reals)
			missing = append(missing, k)
		}
		return dat, fmt.Errorf("missing required args: %s", strings.Join(missing, " "))
	}

	// prompt for password if not in arg list
	if s.PasswordArg != "" && !passwordFound {
		pw, err := getPassword(s.VerifyPassword)
		if err != nil {
			return dat, err
		}
		setKeyVal(dat, resolveAlias(s.PasswordArg, aliases), pw)
	}

	// Specifying obj is used for two purposes.
	// First is to ensure user has specified valid arguments.
	// Second is to convert the values for any non-string fields
	// to their appropriate type.
	if obj != nil {
		unused, err := WeakDecode(dat, obj, s.DecodeHook)
		if err != nil {
			return dat, err
		}
		if !s.AllowUnused && len(unused) > 0 {
			return dat, fmt.Errorf("invalid args: %s",
				strings.Join(unused, " "))
		}

		// This back and forth between yaml is to generate another
		// set of generic map[string]interface{} data that contains
		// typed values instead of string values. The json body
		// values need to be properly typed to be unmarshalled
		// properly, so we replace the specified untyped (string)
		// values with properly typed (bool, int, etc) values.
		// We can't use the typedMap directly because it may
		// contain empty fields that were not specified by the
		// user in the args list, which will mess up updates.
		yaml.AlwaysOmitEmpty = false
		byt, err := yaml.Marshal(obj)
		if err != nil {
			return dat, err
		}
		yaml.AlwaysOmitEmpty = true

		typedDat := make(map[string]interface{})
		err = yaml.Unmarshal(byt, &typedDat)
		if err != nil {
			return dat, err
		}
		replaceMapVals(typedDat, dat)
	}
	return dat, nil
}

func WeakDecode(input, output interface{}, hook mapstructure.DecodeHookFunc) ([]string, error) {
	// use mapstructure.ComposeDecodeHookFunc if we need multiple
	// decode hook functions.
	config := &mapstructure.DecoderConfig{
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook:       hook,
		Metadata:         &mapstructure.Metadata{},
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return []string{}, err
	}
	err = decoder.Decode(input)
	return config.Metadata.Unused, err
}

func resolveAlias(name string, aliases map[string]string) string {
	if real, ok := aliases[name]; ok {
		return real
	}
	return name
}

func setKeyVal(dat map[string]interface{}, key, val string) {
	parts := strings.Split(key, ".")
	for ii, part := range parts {
		if ii == len(parts)-1 {
			// values passed in on the command line that
			// have spaces will be quoted.
			valnew, err := strconv.Unquote(val)
			if err == nil {
				dat[part] = valnew
			} else {
				dat[part] = val
			}
		} else {
			var submap map[string]interface{}
			sub, ok := dat[part]
			if !ok {
				submap = make(map[string]interface{})
				dat[part] = submap
			} else {
				submap, ok = sub.(map[string]interface{})
				if !ok {
					// conflict, overwrite
					submap = make(map[string]interface{})
					dat[part] = submap
				}
			}
			dat = submap
		}
	}
}

func getPassword(verify bool) (string, error) {
	fmt.Printf("password: ")
	pw, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	if verify {
		fmt.Print("verify password: ")
		pw2, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Println()
		if string(pw) != string(pw2) {
			return "", fmt.Errorf("passwords don't match")
		}
	}
	return string(pw), nil
}

func replaceMapVals(src map[string]interface{}, dst map[string]interface{}) {
	for key, dstVal := range dst {
		srcVal, found := src[key]
		if !found {
			continue
		}
		subSrc, ok := srcVal.(map[string]interface{})
		subDst, ok2 := dstVal.(map[string]interface{})
		if ok && ok2 {
			replaceMapVals(subSrc, subDst)
			continue
		}
		//fmt.Printf("replace %s %#v with %#v\n", key, dst[key], src[key])
		dst[key] = src[key]
	}
}

func MarshalArgs(obj interface{}) ([]string, error) {
	args := []string{}
	if obj == nil {
		return args, nil
	}

	// use mobiledgex yaml here since it always omits empty
	byt, err := yaml.Marshal(obj)
	if err != nil {
		return args, err
	}
	dat := make(map[string]interface{})
	err = yaml.Unmarshal(byt, &dat)

	return MapToArgs([]string{}, dat), nil
}

func MapToArgs(prefix []string, dat map[string]interface{}) []string {
	args := []string{}
	for k, v := range dat {
		if sub, ok := v.(map[string]interface{}); ok {
			subargs := MapToArgs(append(prefix, k), sub)
			args = append(args, subargs...)
			continue
		}
		keys := append(prefix, k)
		val := fmt.Sprintf("%v", v)
		if strings.ContainsAny(val, " \t\r\n") {
			val = strconv.Quote(val)
		}
		arg := fmt.Sprintf("%s=%s", strings.Join(keys, "."), val)
		args = append(args, arg)
	}
	return args
}
