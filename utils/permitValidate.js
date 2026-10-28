const permitValidate = (images) => {
  let imagesTable = [];
  if (Array.isArray(images)) {
    imagesTable = images;
  } else {
    imagesTable.push(images);
  }

  if (imagesTable.length > 1) {
    return { error: 'Send only 1 pdf file!' };
  }
  for (let image of imagesTable) {
    if (image.size > 1048576) return { error: 'Size too large (above 1 MB)' };

    const filetypes = /pdf/;
    const mimetype = filetypes.test(image.mimetype);
    if (!mimetype) return { error: 'Incorrect mime type: should be pdf only.' };
  }

  return { error: false };
};

module.exports = permitValidate;
