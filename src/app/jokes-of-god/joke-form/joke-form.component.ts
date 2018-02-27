import { Component, OnInit,Input, Output, EventEmitter} from '@angular/core';
import {JokeTemplate} from '../jokeTemplate';
import {Jokes} from '../Jokelist';
@Component({
  selector: 'app-joke-form',
  templateUrl: './joke-form.component.html',
  styleUrls: ['./joke-form.component.css']
})
export class JokeFormComponent implements OnInit {

  @Output() jokeCreated = new EventEmitter<JokeTemplate>();

  createJoke(set, punch) {
    this.jokeCreated.emit({setup: set, punchline: punch, hide: true, status: 'show'});
  }

  constructor() { }

  ngOnInit() {
  }

}
