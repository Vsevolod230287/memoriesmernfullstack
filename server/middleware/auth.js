import jwt from "jsonwebtoken";

const auth = async (req, res, next) => {
  try {
    console.log(req.headers);
    const token = req.headers.authorization.split(" ")[1];
    
    // token_oAuth(google) > 500 char 
    // token_jwt_custom < 500 char
    const isCustomAuth = token.length < 500;

    let decodedData;

    if (token && isCustomAuth) {
      // "test" === secret_key passed, when we create custom_token
      // secret_key need to be stored in .env that apear in .gitignore
      decodedData = jwt.verify(token, "test");
      req.userId = decodedData?.id;

    } else {
      decodedData = jwt.decode(token);
      // "sub" is the google obj for diferentiate every single user like id 
      req.userId = decodedData?.sub;
    }
    next()
  } catch (error) {
    console.log(error);
  }
};

export default auth