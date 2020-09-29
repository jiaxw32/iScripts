Process.enumerateModulesSync().forEach(function (image) {
  var path = image.path;
  var name = image.name;
  var addr = image.base;
  var size = image.size;
  if (path.indexOf(".app") != -1 || path.indexOf("/Library/MobileSubstrate/") == 0) {
    console.log(
      "image name: " + name + "\n" +
      "base address: " + addr + "\n" +
      "image size: " + size + "\n" +
      "image path: " + path + "\n"
    );
  }
});
