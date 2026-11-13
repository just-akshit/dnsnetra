/* Reusable retrieval-practice quiz component.
   Markup:
   <div class="quiz" data-quiz>
     <div class="quiz-question"
          data-correct="report"
          data-explanation="Correct — saved reports are frozen snapshots."
          data-hint="Not quite. Which artifact is meant to be reproducible?">
       <p class="quiz-prompt">...</p>
       <div class="quiz-options">
         <button type="button" data-option="report">The saved report</button>
         <button type="button" data-option="case">The active case</button>
       </div>
       <p class="quiz-feedback" aria-live="polite"></p>
     </div>
   </div>
*/
(function () {
  "use strict";

  function initQuestion(question) {
    var options = Array.prototype.slice.call(
      question.querySelectorAll("button[data-option]")
    );
    var feedback = question.querySelector(".quiz-feedback");
    var correct = question.getAttribute("data-correct");
    var explanation =
      question.getAttribute("data-explanation") || "Correct.";
    var hint =
      question.getAttribute("data-hint") || "Not quite. Try again.";

    if (!options.length || !feedback) return;

    options.forEach(function (button) {
      button.setAttribute("aria-pressed", "false");

      button.addEventListener("click", function () {
        if (button.disabled) return;

        options.forEach(function (other) {
          other.classList.remove("correct", "wrong");
          other.setAttribute("aria-pressed", "false");
        });

        var chosen = button.getAttribute("data-option");
        button.setAttribute("aria-pressed", "true");

        if (chosen === correct) {
          button.classList.add("correct");
          feedback.textContent = explanation;
          feedback.className = "quiz-feedback is-correct";
          options.forEach(function (other) {
            other.disabled = true;
          });
        } else {
          button.classList.add("wrong");
          feedback.textContent = hint;
          feedback.className = "quiz-feedback is-wrong";
        }
      });
    });
  }

  function init() {
    var quizzes = document.querySelectorAll("[data-quiz]");
    Array.prototype.forEach.call(quizzes, function (quiz) {
      var questions = quiz.querySelectorAll(".quiz-question");
      Array.prototype.forEach.call(questions, initQuestion);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
