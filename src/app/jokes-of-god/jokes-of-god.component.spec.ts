import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { JokesOfGodComponent } from './jokes-of-god.component';

describe('JokesOfGodComponent', () => {
  let component: JokesOfGodComponent;
  let fixture: ComponentFixture<JokesOfGodComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ JokesOfGodComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(JokesOfGodComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
