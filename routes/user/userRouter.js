import express from 'express';
import { deleteUser, loginUser, registerUser, updateUser, updatePicture, updatePassword, sendVerificationCode, verifyCode, updateNickname, updateIntro, getMyFollowing, getMyFollowers, followStatus, toggleFollow, signupVerifyCode, findPhoneNumber, resetPW } from '../../controller/user/user.js';

const userRouter = express.Router();

userRouter.post("/login", loginUser)
userRouter.post("/register", registerUser);
userRouter.put("/update", updateUser);
userRouter.delete("/delete", deleteUser);
userRouter.post("/picture", updatePicture);
userRouter.post("/change-password", updatePassword);
userRouter.post("/change-nickname", updateNickname);
userRouter.post("/change-intro", updateIntro);
userRouter.post("/reset-password", resetPW);
// 문자 인증 관련 라우트
userRouter.post("/send-verification", sendVerificationCode);
userRouter.post("/verify-code", verifyCode);
userRouter.post("/signup-verify-code", signupVerifyCode);
userRouter.post("/findId", findPhoneNumber)
// 팔로워/팔로잉 관련 라우트
userRouter.post("/getMyFollowing", getMyFollowing);
userRouter.post("/getMyFollowers", getMyFollowers);
userRouter.post("/follow-status", followStatus);
userRouter.post("/toggle-follow", toggleFollow);

export default userRouter;