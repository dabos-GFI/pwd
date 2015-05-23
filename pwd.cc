// pwd.cc
#include <node.h>
#include <sys/types.h>
#include <pwd.h>

namespace pwd {

using namespace v8;
  
Local<Object> mkpasswd(Isolate* isolate, const struct passwd *pwd) {
  Local<Object> obj = Object::New(isolate);
  obj->Set(String::NewFromUtf8(isolate, "pw_name"), String::NewFromUtf8(isolate, pwd->pw_name));
  obj->Set(String::NewFromUtf8(isolate, "pw_uid"), Number::New(isolate, pwd->pw_uid));
  obj->Set(String::NewFromUtf8(isolate, "pw_gid"), Number::New(isolate, pwd->pw_gid));
  obj->Set(String::NewFromUtf8(isolate, "pw_dir"), String::NewFromUtf8(isolate, pwd->pw_dir));
  obj->Set(String::NewFromUtf8(isolate, "pw_shell"), String::NewFromUtf8(isolate, pwd->pw_shell));

  // NOT SUPPORTED IN V1.1.0
  //  pw_passwd - encrypted password
  //  pw_change - password change time
  //  pw_class  - user access class
  //  pw_gecos  - Honeywell login info
  //  pw_expire - account expiration
  //  pw_fields - internal: fields filled in
  return obj;
}

void Getpwuid(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  
  if (args.Length() < 1) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
  }

  if (!args[0]->IsNumber()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Argument must be a number")));
    return;
  }

  uid_t uid = args[0]->NumberValue();

  struct passwd *pwd = getpwuid(uid);

  if (pwd != NULL) {
    args.GetReturnValue().Set(mkpasswd(isolate, pwd));
  }
}
  
void Getpwnam(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  
  if (args.Length() < 1) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
  }

  if (!args[0]->IsString()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Argument must be a string")));
    return;
  }

  String::Utf8Value name(args[0]);

  struct passwd *pwd = getpwnam(*name);

  if (pwd != NULL) {
    args.GetReturnValue().Set(mkpasswd(isolate, pwd));
  }
}

void Init(Local<Object> exports, Local<Object> module) {
  NODE_SET_METHOD(exports, "getpwuid", Getpwuid);
  NODE_SET_METHOD(exports, "getpwnam", Getpwnam);
}

NODE_MODULE(addon, Init)

}  // namespace pwd

