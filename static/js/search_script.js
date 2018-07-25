lsearch = function(search,data){
  //this.term = document.getElementById('S').value.toUpperCase();
  var s = document.getElementById(search).value.toLowerCase();
  rows = document.getElementById(data).getElementsByTagName('tr');
  for(var i=0;i<rows.length;i++){
    if (rows[i].id != 'none'){
      if (s =="" ){
        rows[i].style.display ='';
      } else if ( rows[i].innerText.toLowerCase().indexOf(s) != -1 ) {
        rows[i].style.display ='';
      } else {
        rows[i].style.display ='none';
      }
    }
  }
  this.time = false;
}