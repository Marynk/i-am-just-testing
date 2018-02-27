import { AngularFireDatabase } from 'angularfire2/database';
import { database } from 'firebase';
import { Component, OnInit, Input, } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import {JokeTemplate} from '../jokeTemplate';

@Component({
  selector: 'app-joke',
  templateUrl: './joke.component.html',
  styleUrls: ['./joke.component.css']
})


export class JokeComponent  {

  res: Observable<any[]>;

  toggle(joke): void {
 
    joke.hide = !joke.hide;

    if (!joke.hide) {
      joke.status = 'hide';
    } else {
      joke.status = 'show';
    }
  }

  addJoke(joke) {

    database().ref('/jokes/' + joke.setup).set(joke);
  }

  delete(joke){
    database().ref('/jokes/' + joke.setup).remove();
  }

  constructor(db: AngularFireDatabase) {

      this.res = db.list('/jokes').valueChanges();
      // subscribe(res => {this.res = res; console.log(this.res);});
    }

}
