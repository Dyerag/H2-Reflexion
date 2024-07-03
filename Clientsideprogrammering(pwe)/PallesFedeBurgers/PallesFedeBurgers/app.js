const listEL = document.querySelector("ul");

fetch("./burgers.json")
  .then((res) => res.json())
  .then((data) => {
    data.forEach((x) => {
      listEL.insertAdjacentHTML("beforeend", `<li>${x.title} ${x.body}</li>`);
    });
  });
