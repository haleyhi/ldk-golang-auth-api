package keytar

/*
#cgo pkg-config: glib-2.0 libsecret-1

// Standard includes
#include <stdlib.h>
#include <string.h>

// GNOME includes
#include <glib.h>
#include <libsecret/secret.h>

const SecretSchema * example_get_schema (void) G_GNUC_CONST;

#define EXAMPLE_SCHEMA  example_get_schema ()


// in a .c file:

const SecretSchema *
example_get_schema (void)
{
    static const SecretSchema the_schema = {
        "org.example.Password", SECRET_SCHEMA_NONE,
        {
            {  "number", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
			{  "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "account", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "even", SECRET_SCHEMA_ATTRIBUTE_BOOLEAN },
            {  "NULL", 0 },
        }
    };
    return &the_schema;
}

// Adds a password to the default keychain.  All arguments must be UTF-8 encoded
// and null-terminated.
int addPassword(
	const char * displayName,
	const char * service,
	const char * account,
	const char * password
) {

	 GError *error = NULL;

	//
	// The variable argument list is the attributes used to later
	// lookup the password. These attributes must conform to the schema.

	secret_password_store_sync (EXAMPLE_SCHEMA, SECRET_COLLECTION_DEFAULT,
		displayName, password, NULL, &error,
		"service", service,
		"account", account,
		NULL);

	if (error != NULL) {
	    // ... handle the failure here
	    g_error_free (error);
		return -1;
	} else {
	// ... do something now that the password has been stored
	    return 0;
	}

}




// Gets a password from the default keychain.  All arguments must be UTF-8
// encoded and null-terminated.  On success, the password argument will be set
// to a null-terminated string that must be released with free.
int getPassword(const char * service, const char * account, char ** password) {

	GError *error = NULL;

	// The attributes used to lookup the password should conform to the schema.
	gchar *result = secret_password_lookup_sync (EXAMPLE_SCHEMA, NULL, &error,
		"service", service,
		"account", account,
		NULL);

	if (error != NULL) {
		// ... handle the failure here
		g_error_free (error);
		*password = NULL;
		return -1;

	} else if (result == NULL) {
		// password will be null, if no matching password found
		*password = NULL;
		return -1;

	} else {
			*password = malloc(strlen(result) + 1);
	        strcpy(*password, result);
	        // ... do something with the password
	        secret_password_free (result);
	}

	// All done
	return 0;
}

// Deletes a password from the default keychain.  All arguments must be UTF-8
// encoded and null-terminated.
int deletePassword(const char * service, const char * account) {

	GError *error = NULL;


	// The variable argument list is the attributes used to later
	// lookup the password. These attributes must conform to the schema.

	gboolean removed = secret_password_clear_sync (EXAMPLE_SCHEMA, NULL, &error,
		"service", service,
		"account", account,
		NULL);

	if (error != NULL) {
		// ... handle the failure here
		g_error_free (error);
		return -1;

	} else {
		// removed will be TRUE if a password was removed
	}

	// All done
	return 0;
}
*/
import "C"

import (
	// System imports
	"fmt"
	"unsafe"
)

// keychainLinux implements the Keychain interface on Linux by using the
// GNOME Keyring infrastructure to store items in the user's keyring.
type keychainLinux struct{}

func (*keychainLinux) AddPassword(service, account, password string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	passwordValid := isValidNonNullUTF8(password)
	if !(serviceValid && accountValid && passwordValid) {
		return ErrInvalidValue
	}

	// Compute a display name and convert it to a C string
	display := fmt.Sprintf("%s@%s", service, account)

	// Convert values to C strings
	displayCStr := C.CString(display)
	defer C.free(unsafe.Pointer(displayCStr))
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))
	passwordCStr := C.CString(password)
	defer C.free(unsafe.Pointer(passwordCStr))

	// Do the add and check for errors
	if C.addPassword(displayCStr, serviceCStr, accountCStr, passwordCStr) < 0 {
		return ErrUnknown
	}

	// All done
	return nil
}

func (*keychainLinux) GetPassword(service, account string) (string, error) {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return "", ErrInvalidValue
	}

	// Convert values to C strings
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))

	// Get the password and check for errors
	var passwordCStr *C.char
	if C.getPassword(serviceCStr, accountCStr, &passwordCStr) < 0 {
		return "", ErrNotFound
	}

	// If there was a match, convert it and free the underlying C string
	password := C.GoString(passwordCStr)
	C.free(unsafe.Pointer(passwordCStr))

	// All done
	return password, nil
}

func (*keychainLinux) DeletePassword(service, account string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return ErrInvalidValue
	}

	// Convert values to C strings
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))

	// Delete the password and check for errors
	if C.deletePassword(serviceCStr, accountCStr) < 0 {
		return ErrUnknown
	}

	// All done
	return nil
}

func init() {
	// Register the Linux keychain implementation if keychain services are
	// available
	keychain = &keychainLinux{}
}
