<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
	<title>Home</title>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">


	<!-- Animate.css -->
	<link rel="stylesheet" href="/controller/resources/css/animate.css">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="/controller/resources/css/icomoon.css">

	<!-- Owl Carousel -->
	<link rel="stylesheet" href="/controller/resources/css/owl.carousel.min.css">
	<link rel="stylesheet" href="/controller/resources/css/owl.theme.default.min.css">
	<!-- Theme style  -->
	<link rel="stylesheet" href="/controller/resources/css/style.css">
	<!-- Modernizr JS -->
	<script src="/controller/resources/js/modernizr-2.6.2.min.js"></script>	
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
	
<section id="container">
 
  <form role="form" method="post" autocomplete="off">
  <h2>교환/반품/환불</h2>
   <p>
   	<label for ="as_no"></label><input type ="hidden" id ="no" name ="as_no" value ="${read.as_no}" readonly = "readonly"/>
   </p>
   </form>
   <p>
   	<label for ="order_no">주문번호</label><input type ="text" id ="order_no" name ="order_no" value ="${read.order_no}" readonly ="readonly"/>
   </p>
    <p>
    <label for="member_id">작성자</label><input type ="text" id="member_id" name="member_id" value="${read.member_id}" readonly = "readonly" />
   </p>
   <p>
    <label for="as_title">제목</label><input type="text" id="title" name="as_title" value ="${read.as_title}" readonly= "readonly"/>
   </p>
    <p>
    	<label for ="as_category">분류</label><input type ="text" id ="category" name ="as_category" value ="${read.as_category}" readonly ="readonly" />
 
  
   <p>
    <label for="as_content">사유</label><input type ="text" id="content" name="as_content" value="${read.as_content}" placeholder="사유를 입력하세요." readonly="readonly"/>
   </p>
   <p>
   	<label for ="as_account">환불 계좌</label>
   	<select readonly ="readonly">
   		<option title ="">은행명</option>
   		<option value ="국민">국민</option>
   		<option value ="신한">신한</option>
   		<option value ="농협">농협</option>
	</select>
   	<input type ="text" id ="account" name ="as_account" value="${read.as_account}" readonly = "readonly"/>
   </p>
   <p>
   	<label>작성 날짜</label> <span><fmt:formatDate value="${read.as_regdate}" pattern="yyyy-MM-dd" /></span>
   </p>
   <p>
   	<button id ="modify_btn">수정</button>
   	<button id ="delete_btn">삭제</button>
   	
   	<script>
		var formObj = $("form[role='form']");
		//수정 버튼
		$("#modify_btn").click(function(){

			formObj.attr("action", "./myASModify");
			formObj.attr("method", "get");
			formObj.submit();
			
			});
		//삭제버튼
		$("#delete_btn").click(function(){

			formObj.attr("action", "./myASRemove");
			formObj.attr("method", "get");
			formObj.submit();
			
			});
		
   	</script>
   </p>
  

 </section>


<jsp:include page="../common/footer.jsp"></jsp:include>
<!-- jQuery -->
	<script src="/controller/resources/js/jquery.min.js"></script>
	<!-- jQuery Easing -->
	<script src="/controller/resources/js/jquery.easing.1.3.js"></script>
	<!-- Bootstrap -->
	<script src="/controller/resources/js/bootstrap.min.js"></script>
	<!-- Carousel -->
	<script src="/controller/resources/js/owl.carousel.min.js"></script>
	<!-- Stellar -->
	<script src="/controller/resources/js/jquery.stellar.min.js"></script>
	<!-- Waypoints -->
	<script src="/controller/resources/js/jquery.waypoints.min.js"></script>
	<!-- Counters -->
	<script src="/controller/resources/js/jquery.countTo.js"></script>
	<!-- MAIN JS -->
	<script src="/controller/resources/js/main.js"></script>

</body>
</html>