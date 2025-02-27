import otherPhoto from '../../models/otherPhoto_schema.js';
import Other from '../../models/other_schema.js'

const addPhoto = async () => {
     try {
         const other = await Other.findOne({ title: "대나무 칫솔" });
         if (!other) throw new Error("상품 없음");
 
         console.log("찾은 상품:", other); // 확인용 로그
 
         const photo = await otherPhoto.create({
             other: other._id, // 필드명 확인
             url: "https://lovegan-photo-bucket.s3.ap-northeast-2.amazonaws.com/tooth+brush.jpg"
         });

         await photo.save();
 
         console.log("생성된 otherPhoto:", photo); // 생성 여부 확인
 
         if (!other) {
             console.error("OtherPhoto 생성 실패");
             return;
         }
 
         other.photoId = other._id; // Other에 photoId 연결
         await other.save();
 
         console.log("사진 추가 완료");
     } catch (error) {
         console.error("에러 발생:", error);
     }
 };
 
 addPhoto();

const getOther = async (req, res) => {
     const {categories, tag, clickSort} = req.query;
     console.log(clickSort);
     let sortName = "like"
     let sortValue = -1;
     if (clickSort) {
          if(clickSort==="like"){
               sortName = "star";
               sortValue = -1;
          }
          else if(clickSort==="lowCost"){
               sortName = "price";
               sortValue = 1;
          }
          else if(clickSort==="highCost"){
               sortName = "price";
               sortValue = -1;
          }
          else if(clickSort === "review"){
               sortName = "review";
               sortValue = -1
          }
          else{
               sortName = "review";
               sortValue = -1
          }
     }
     try {
          // 조건 객체를 동적으로 생성
          const filter = {};
          if (categories) filter.categories = categories; 
          if (tag) filter.tag = tag;
         
  
          // 조건에 맞는 데이터 검색
          const otherLists = await Other.find(filter).sort({[sortName] : sortValue});
          res.json(otherLists); // 결과 반환
      } catch (error) {
          console.error("상품 데이터를 가져오는 중 오류 발생:", error);
          res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답
      }
};
const postOther = async (req, res) => {
     const {id} = req.query;
     console.log(id)

     try{
          const OtherDetail = await Other.findById(id);
          res.json(OtherDetail);

     }catch(error){
          console.error("상품 데이터를 가져오는 중 오류 발생:", error);
          res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답
     }
   
};


export {getOther, postOther}