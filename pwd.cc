#include <node.h>
#include <v8.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

using namespace v8;


Local<Object> mkpasswd(const struct passwd *pwd) {
  Local<Object> obj = Object::New();
  obj->Set(String::NewSymbol("pw_name"), String::New(pwd->pw_name));
  obj->Set(String::NewSymbol("pw_uid"), Number::New(pwd->pw_uid));
  obj->Set(String::NewSymbol("pw_gid"), Number::New(pwd->pw_gid));
  obj->Set(String::NewSymbol("pw_dir"), String::New(pwd->pw_dir));
  obj->Set(String::NewSymbol("pw_shell"), String::New(pwd->pw_shell));

  // NOT SUPPORTED IN V1.0.0
  //  pw_passwd - encrypted password
  //  pw_change - password change time
  //  pw_class  - user access class
  //  pw_gecos  - Honeywell login info
  //  pw_expire - account expiration
  //  pw_fields - internal: fields filled in
  return obj;
}


Local<Object> mkgroup(const struct group *grp) {
  Local<Object> obj = Object::New();
  Local<Array> mems = Array::New();
  int i = 0;

  obj->Set(String::NewSymbol("gr_name"), String::New(grp->gr_name));
  obj->Set(String::NewSymbol("gr_passwd"), String::New(grp->gr_passwd));
  obj->Set(String::NewSymbol("gr_gid"), Number::New(grp->gr_gid));

  while(grp->gr_mem[i] != NULL) {
    mems->Set(Integer::New(i), String::New(grp->gr_mem[i]));
    i++;
  }

  obj->Set(String::NewSymbol("gr_mem"), mems);

  return obj;
}


Handle<Value> Getpwuid(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 0) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }

  if (!args[0]->IsNumber()) {
    ThrowException(Exception::TypeError(String::New("Argument must be a number")));
    return scope.Close(Undefined());
  }

  uid_t uid = args[0]->NumberValue();

  struct passwd *pwd = getpwuid(uid);

  if (pwd == NULL) {
    return scope.Close(Undefined());
  } else {
    return scope.Close(mkpasswd(pwd));
  }
}


Handle<Value> Getpwnam(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 0) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }

  if (!args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Argument must be a string")));
    return scope.Close(Undefined());
  }

  String::Utf8Value name(args[0]);

  struct passwd *pwd = getpwnam(*name);

  if (pwd == NULL) {
    return scope.Close(Undefined());
  } else {
    return scope.Close(mkpasswd(pwd));
  }
}


Handle<Value> Getgrnam(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 0) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }

  if (!args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Argument must be a string")));
    return scope.Close(Undefined());
  }

  String::Utf8Value name(args[0]);

  struct group *grp = getgrnam(*name);

  if (grp == NULL) {
    return scope.Close(Undefined());
  } else {
    return scope.Close(mkgroup(grp));
  }
}


Handle<Value> Getgrgid(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 0) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }

  if (!args[0]->IsNumber()) {
    ThrowException(Exception::TypeError(String::New("Argument must be a number")));
    return scope.Close(Undefined());
  }

  gid_t gid = args[0]->NumberValue();

  struct group *grp = getgrgid(gid);

  if (grp == NULL) {
    return scope.Close(Undefined());
  } else {
    return scope.Close(mkgroup(grp));
  }
}


void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("getpwuid"),
    FunctionTemplate::New(Getpwuid)->GetFunction());
  exports->Set(String::NewSymbol("getpwnam"),
    FunctionTemplate::New(Getpwnam)->GetFunction());
  exports->Set(String::NewSymbol("getgrnam"),
    FunctionTemplate::New(Getgrnam)->GetFunction());
  exports->Set(String::NewSymbol("getgrgid"),
    FunctionTemplate::New(Getgrgid)->GetFunction());
}

NODE_MODULE(pwd, init)

