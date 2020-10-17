/*
 * Auto-generated by Frida. Please modify to match the signature of -[NSMutableURLRequest setAllHTTPHeaderFields:].
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  /**
   * Called synchronously when about to call -[NSMutableURLRequest setAllHTTPHeaderFields:].
   *
   * @this {object} - Object allowing you to store state for use in onLeave.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Function arguments represented as an array of NativePointer objects.
   * For example use args[0].readUtf8String() if the first argument is a pointer to a C string encoded as UTF-8.
   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
   * @param {object} state - Object allowing you to keep state across function calls.
   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
   * However, do not use this to store function arguments across onEnter/onLeave, but instead
   * use "this" which is an object for keeping state local to an invocation.
   */
  onEnter: function (log, args, state) {
    var dict = new ObjC.Object(args[2]);
    var enumerator = dict.keyEnumerator();
    var key;
    while ((key = enumerator.nextObject()) !== null) {
      var value = dict.objectForKey_(key);
      ['cookie', 'user-agent', 'accept'].forEach(function (item, i) {
        if (key.toString().toLocaleLowerCase() == item.toLocaleLowerCase()) {
          log("\tBacktrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"));
        }
      })
    }
    // log('-[NSMutableURLRequest setAllHTTPHeaderFields:]' + dict.toString());
  }
}