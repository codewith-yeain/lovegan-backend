import ProductPhoto from '../../models/productPhoto_schema.js';
import Product from '../../models/product_schema.js'

const addPhoto = async () => {
     try {
         const product = await Product.findOne({ title: "강황미 1kg" });
         if (!product) throw new Error("상품 없음");
 
         console.log("찾은 상품:", product); // 확인용 로그
 
         const photo = await ProductPhoto.create({
             product: product._id, // 필드명 확인
             url: "https://lovegan-photo-bucket.s3.ap-northeast-2.amazonaws.com/yellow+meal.jpg"
         });

         await photo.save();
 
         console.log("생성된 ProductPhoto:", photo); // 생성 여부 확인
 
         if (!photo) {
             console.error("ProductPhoto 생성 실패");
             return;
         }
 
         product.photoId = photo._id; // Product에 photoId 연결
         await product.save();

     // photoId가 배열이라면 push 사용
     // await Product.updateOne(
     //      { _id: product._id },
     //      { $push: { photoId: photo._id } } // 배열에 추가
     //  );

 
         console.log("사진 추가 완료");
     } catch (error) {
         console.error("에러 발생:", error);
     }
 };
 
 addPhoto();

const getProduct = async (req, res) => {
     const {categories, tag, clickSort} = req.query;
     //console.log(id);
     
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
          const productLists = await Product.find(filter)
          .sort({[sortName] : sortValue})
          .populate("photoId");

          res.json(productLists); // 결과 반환
      } catch (error) {
          console.error("상품 데이터를 가져오는 중 오류 발생:", error);
          res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답
      }
};
const postProduct = async (req, res) => {
     const {id} = req.query;
     console.log(id)

     try{
          const productDetail = await Product.findById(id);
          res.json(productDetail);

     }catch(error){
          console.error("상품 데이터를 가져오는 중 오류 발생:", error);
          res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답
     }
   
};


export {getProduct, postProduct}