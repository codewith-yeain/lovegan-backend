import express from "express";
import passport from "passport";
import { localStrategy, jwtStrategy } from "../../controller/auth/auth.js";



const authRouter = express.Router();
const clientUrl = "http://localhost:3000"
// auth
// passport 라우팅
authRouter.post("/local", passport.authenticate('local', {session : false}), localStrategy);
authRouter.post("/jwt", passport.authenticate('jwt', {session : false}), jwtStrategy);

// 네이버 로그인
authRouter.get("/naver", passport.authenticate('naver', { session : false, authType : 'reprompt'}));
authRouter.get("/naver/callback", passport.authenticate('naver', {session : false, failureRedirect : clientUrl}), (req, res) => {
    console.log("네이버 로그인 후 유저의 정보", req.user)
    const accessToken = req.user.accessToken;
    return res.redirect(clientUrl);
});

// 구글 로그인
authRouter.get("/google", passport.authenticate('google', { session : false, scope : ['profile', 'email']}));
authRouter.get("/google/callback", passport.authenticate('google', { session : false, failureRedirect : clientUrl}), (req, res) => {
    console.log("구글 로그인 후 유저의 정보", req.user)
    const accessToken = req.user.accessToken;
    return res.redirect(`${clientUrl}/my?accessToken=${accessToken}`);
});

export default authRouter;


// sns 로그인 후 session에 사용자가 존재하는지 여부를 확인하기
// authRouter.get('/profile', (req, res)=> {
//     // session user가 있으면 true 없으면 false
//     console.log(req.isAuthenticated())
//     if(!req.isAuthenticated()){
//         return res.redirect("/");
//     }
//     const {email, name, createAt, phone} = req.user;
//     res.status(200).json({
//         user : {email, name, createAt, phone},
//         isLogin : true,
//         message : "로그인이 되었습니다."
//     })
// })