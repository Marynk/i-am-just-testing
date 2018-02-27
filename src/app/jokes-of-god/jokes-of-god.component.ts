import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-jokes-of-god',
  templateUrl: './jokes-of-god.component.html',
  styleUrls: ['./jokes-of-god.component.scss']
})
export class JokesOfGodComponent implements OnInit {
 title = 'Jokes are here!';
  constructor() { }

  ngOnInit() {
  }

}
