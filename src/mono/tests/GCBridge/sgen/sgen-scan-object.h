MonoObject *_o = (MonoObject*)start;
for (int _i = 0; _i < _o->ref_count; _i++) {
    if (_o->refs[_i] != NULL) {
        HANDLE_PTR((&_o->refs[_i]), _o);
    }
}